/*
 * server.cpp
 * 
 * Implements a standalone computation server (Party 0 or Party 1) in the 3-party DUORAM system.
 * 
 * Key architectural features:
 * 1. Role-based connection dispatching:
 *    - ROLE_OFFLINE (1): Dealer connection streaming precomputed (dpf_id, r_share, DPFKey).
 *    - ROLE_ONLINE  (2): Client connection issuing oblivious reads and writes.
 *    - ROLE_PEER    (3): Dedicated inter-server TCP channel for shift exchange and MPC evaluation.
 * 2. Pure XOR-permutation protocol:
 *    - Servers pop offline item (dpf_id, r_share, expanded_vector).
 *    - Given target index share t_share from client, server computes shift share c_share = t_share ^ r_share.
 *    - Servers exchange shift shares over peer TCP channel and reconstruct public shift c = c0 ^ c1 = t ^ r.
 *    - Database evaluation uses XOR permutations: DB[i ^ c] instead of cyclic shifts modulo N.
 */

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"
#include "pool.hpp"

using boost::asio::ip::tcp;

class Server {
public:
    Server(boost::asio::io_context& io_context,
           int party_id,
           short port,
           const std::string& peer_host,
           short peer_port,
           size_t db_blocks)
        : io_context_(io_context),
          acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          party_id_(party_id),
          peer_host_(peer_host),
          peer_port_(peer_port),
          db_(db_blocks),
          depth_(__builtin_ctzll(db_blocks)),
          offline_pool_(200),
          peer_connected_(false)
    {
        do_accept();

        // Party 1 actively connects to Party 0; Party 0 passively accepts Party 1
        if (party_id_ == 1) {
            connect_to_peer_thread_ = std::thread([this]() {
                connect_to_peer_loop();
            });
        }
    }

    ~Server() {
        if (connect_to_peer_thread_.joinable()) {
            connect_to_peer_thread_.join();
        }
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::thread([this, s = std::move(socket)]() mutable {
                        dispatch_connection(std::move(s));
                    }).detach();
                }
                do_accept();
            });
    }

    void dispatch_connection(tcp::socket socket) {
        try {
            uint8_t role = 0;
            boost::asio::read(socket, boost::asio::buffer(&role, 1));

            if (role == ROLE_OFFLINE) {
                handle_offline_producer(std::move(socket));
            } else if (role == ROLE_ONLINE) {
                handle_online_client(std::move(socket));
            } else if (role == ROLE_PEER) {
                handle_peer_server(std::move(socket));
            } else {
                std::cerr << "[Server " << party_id_ << "] Unknown connection role: " 
                          << int(role) << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[Server " << party_id_ << "] Connection error during dispatch: " 
                      << e.what() << std::endl;
        }
    }

    // Connect loop for Party 1 to reach Party 0
    void connect_to_peer_loop() {
        while (!peer_connected_) {
            try {
                auto s = std::make_unique<tcp::socket>(io_context_);
                tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(peer_host_, std::to_string(peer_port_));
                boost::asio::connect(*s, endpoints);

                uint8_t role = ROLE_PEER;
                boost::asio::write(*s, boost::asio::buffer(&role, 1));

                {
                    std::lock_guard<std::mutex> lock(peer_mutex_);
                    peer_socket_ = std::move(s);
                    peer_connected_ = true;
                }
                peer_cv_.notify_all();
                std::cout << "[Server " << party_id_ << "] Successfully connected to peer Server 0." << std::endl;
                break;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }
    }

    // Handler for incoming peer connection (Party 0 accepting Party 1)
    void handle_peer_server(tcp::socket socket) {
        {
            std::lock_guard<std::mutex> lock(peer_mutex_);
            peer_socket_ = std::make_unique<tcp::socket>(std::move(socket));
            peer_connected_ = true;
        }
        peer_cv_.notify_all();
        std::cout << "[Server " << party_id_ << "] Peer connection established." << std::endl;
    }

    void wait_for_peer() {
        std::unique_lock<std::mutex> lock(peer_mutex_);
        peer_cv_.wait(lock, [this]() { return peer_connected_ && peer_socket_ && peer_socket_->is_open(); });
    }

    // Sequential ping-pong shift share exchange: ensures zero deadlock
    uint64_t exchange_shift(uint64_t my_share) {
        wait_for_peer();
        std::lock_guard<std::mutex> lock(peer_mutex_);
        uint64_t other_share = 0;

        if (party_id_ == 0) {
            write_uint64(*peer_socket_, my_share);
            read_uint64(*peer_socket_, other_share);
        } else {
            read_uint64(*peer_socket_, other_share);
            write_uint64(*peer_socket_, my_share);
        }

        return my_share ^ other_share;
    }

    // Sequential ping-pong shifted database share exchange
    void exchange_shifted_db(const std::vector<Block128>& my_shifted, std::vector<Block128>& peer_shifted) {
        wait_for_peer();
        std::lock_guard<std::mutex> lock(peer_mutex_);

        if (party_id_ == 0) {
            write_blocks(*peer_socket_, my_shifted);
            read_blocks(*peer_socket_, peer_shifted);
        } else {
            read_blocks(*peer_socket_, peer_shifted);
            write_blocks(*peer_socket_, my_shifted);
        }
    }

    // Background handler for streaming pre-computed DPF items from Dealer
    void handle_offline_producer(tcp::socket socket) {
        try {
            std::cout << "[Server " << party_id_ << "] Offline key producer (Dealer) connected." << std::endl;
            while (true) {
                uint64_t dpf_id;
                read_uint64(socket, dpf_id);

                uint64_t r_share;
                read_uint64(socket, r_share);

                DPFKey key;
                read_key(socket, key);

                // Pre-expand key into full boolean vector offline (O(1) online CPU optimization)
                std::vector<bool> expanded = DPF::evaluate_full(key, depth_);

                // Push to thread-safe FIFO queue (blocks if queue reaches capacity for backpressure)
                if (!offline_pool_.push(ServerPoolItem{dpf_id, r_share, std::move(expanded)})) {
                    break;
                }

                uint8_t ack = 1;
                boost::asio::write(socket, boost::asio::buffer(&ack, 1));
            }
        } catch (const std::exception& e) {
            std::cout << "[Server " << party_id_ << "] Offline producer channel disconnected: " 
                      << e.what() << std::endl;
        }
    }

    // Handler for online queries (reads and writes) from Client
    void handle_online_client(tcp::socket socket) {
        try {
            std::cout << "[Server " << party_id_ << "] Online client channel connected." << std::endl;
            while (true) {
                uint8_t cmd = 0;
                boost::asio::read(socket, boost::asio::buffer(&cmd, 1));

                if (cmd == CMD_READ) {
                    uint64_t t_share = 0;
                    read_uint64(socket, t_share);

                    ServerPoolItem pool_item;
                    if (!offline_pool_.pop(pool_item)) {
                        std::cerr << "[Server " << party_id_ << "] Error: Offline pool empty during read!" << std::endl;
                        Block128 zero;
                        write_block(socket, zero);
                        continue;
                    }

                    // Compute shift share c_share = t_share ^ r_share
                    uint64_t c_share = t_share ^ pool_item.r_share;

                    // Exchange shift share with peer server: c = c0 ^ c1 = t ^ r
                    uint64_t c = exchange_shift(c_share);

                    // Compute shifted local database share: my_shifted[i] = db_[i ^ c]
                    size_t n = db_.size();
                    std::vector<Block128> my_shifted(n);
                    {
                        std::lock_guard<std::mutex> lock(db_mutex_);
                        for (size_t i = 0; i < n; ++i) {
                            my_shifted[i] = db_[i ^ c];
                        }
                    }

                    // Exchange shifted shares between servers
                    std::vector<Block128> peer_shifted;
                    exchange_shifted_db(my_shifted, peer_shifted);

                    // Reconstruct shifted database between servers
                    for (size_t i = 0; i < n; ++i) {
                        my_shifted[i] ^= peer_shifted[i];
                    }

                    // Evaluate DPF control vector against shifted database:
                    // sum_{i} (v[i] * my_shifted[i])
                    Block128 accumulator;
                    for (size_t i = 0; i < n; ++i) {
                        if (pool_item.expanded_vector[i]) {
                            accumulator ^= my_shifted[i];
                        }
                    }

                    // Return share to client
                    write_block(socket, accumulator);

                } else if (cmd == CMD_ONLINE_WRITE) {
                    uint64_t t_share = 0;
                    read_uint64(socket, t_share);

                    Block128 V;
                    read_block(socket, V);

                    ServerPoolItem pool_item;
                    if (!offline_pool_.pop(pool_item)) {
                        std::cerr << "[Server " << party_id_ << "] Error: Offline pool empty during write!" << std::endl;
                        uint8_t ack = 0;
                        boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                        continue;
                    }

                    // Compute shift share c_share = t_share ^ r_share
                    uint64_t c_share = t_share ^ pool_item.r_share;

                    // Exchange shift share with peer server
                    uint64_t c = exchange_shift(c_share);

                    // Apply XOR-permutation write directly to secret-shared database:
                    // db_[i ^ c] ^= V if pool_item.expanded_vector[i]
                    size_t n = db_.size();
                    {
                        std::lock_guard<std::mutex> lock(db_mutex_);
                        for (size_t i = 0; i < n; ++i) {
                            if (pool_item.expanded_vector[i]) {
                                db_[i ^ c] ^= V;
                            }
                        }
                    }

                    uint8_t ack = 1;
                    boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                }
            }
        } catch (const std::exception& e) {
            std::cout << "[Server " << party_id_ << "] Online client disconnected: " 
                      << e.what() << std::endl;
        }
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    int party_id_;
    std::string peer_host_;
    short peer_port_;

    std::mutex db_mutex_;
    std::vector<Block128> db_;
    size_t depth_;
    ThreadSafeQueue<ServerPoolItem> offline_pool_;

    std::mutex peer_mutex_;
    std::condition_variable peer_cv_;
    std::unique_ptr<tcp::socket> peer_socket_;
    bool peer_connected_;
    std::thread connect_to_peer_thread_;
};

int main(int argc, char* argv[]) {
    int party_id = 0;
    short port = 8000;
    std::string peer_host = "127.0.0.1";
    short peer_port = 8001;
    size_t total_chars = 1024;

    if (argc == 6) {
        party_id = std::atoi(argv[1]);
        port = std::atoi(argv[2]);
        peer_host = argv[3];
        peer_port = std::atoi(argv[4]);
        total_chars = 1ULL << std::atoi(argv[5]);
    } else if (argc == 3) {
        // Backward-compatible 2-argument mode
        port = std::atoi(argv[1]);
        total_chars = 1ULL << std::atoi(argv[2]);
        if (port == 8000) {
            party_id = 0;
            peer_host = "127.0.0.1";
            peer_port = 8001;
        } else {
            party_id = 1;
            peer_host = "127.0.0.1";
            peer_port = 8000;
        }
    } else {
        std::cerr << "Usage: server <party_id> <port> <peer_host> <peer_port> <db_size_power_of_2_chars>\n"
                  << "  Or:  server <port> <db_size_power_of_2_chars>\n";
        return 1;
    }

    size_t db_blocks = std::max(size_t(1), total_chars / 32);

    boost::asio::io_context io_context;
    Server server(io_context, party_id, port, peer_host, peer_port, db_blocks);

    std::cout << "[Server " << party_id << "] Listening on port " << port 
              << " (Peer: " << peer_host << ":" << peer_port << ")"
              << " with DB capacity " << total_chars << " chars (" << db_blocks << " blocks)\n";
    io_context.run();

    return 0;
}
