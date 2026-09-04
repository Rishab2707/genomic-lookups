/*
 * server.cpp
 * 
 * Implements a standalone background server process acting as one of the 
 * computation parties (P0 or P1) in the networked 2-party system.
 * Implements the pre-computed Cryptographic Pooling (Producer-Consumer) DUORAM architecture.
 */
#include <iostream>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"
#include "pool.hpp"

using boost::asio::ip::tcp;

class Server {
public:
    Server(boost::asio::io_context& io_context, short port, size_t db_blocks)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), 
          db_(db_blocks), 
          depth_(__builtin_ctzll(db_blocks)),
          offline_pool_(100) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    // Dispatch incoming connection to appropriate handler based on role handshake
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
            } else {
                std::cerr << "[Server] Unknown connection role: " << int(role) << std::endl;
            }
        } catch (std::exception& e) {
            std::cout << "[Server] Connection error during dispatch: " << e.what() << std::endl;
        }
    }

    // Background handler for streaming pre-computed Leafless DPF keys
    void handle_offline_producer(tcp::socket socket) {
        try {
            std::cout << "[Server] Offline key producer channel connected." << std::endl;
            while (true) {
                uint64_t dpf_id;
                read_uint64(socket, dpf_id);
                
                DPFKey key;
                read_key(socket, key);
                
                // Pre-expand key into full boolean vector offline (O(1) online CPU optimization)
                std::vector<bool> expanded = DPF::evaluate_full(key, depth_);
                
                // Push to thread-safe FIFO queue (blocks if queue reaches 100 for TCP backpressure)
                if (!offline_pool_.push(ServerPoolItem{dpf_id, std::move(expanded)})) {
                    break;
                }
                
                uint8_t ack = 1;
                boost::asio::write(socket, boost::asio::buffer(&ack, 1));
            }
        } catch (std::exception& e) {
            std::cout << "[Server] Offline producer channel disconnected: " << e.what() << std::endl;
        }
    }

    // Handler for O(1) online queries (reads and writes)
    void handle_online_client(tcp::socket socket) {
        try {
            std::cout << "[Server] Online client channel connected." << std::endl;
            while (true) {
                uint8_t cmd;
                boost::asio::read(socket, boost::asio::buffer(&cmd, 1));
                
                if (cmd == CMD_READ) { // Direct read for secret-shared DB
                    uint64_t block_index;
                    read_uint64(socket, block_index);
                    
                    Block128 val;
                    {
                        std::lock_guard<std::mutex> lock(db_mutex_);
                        if (block_index < db_.size()) {
                            val = db_[block_index];
                        }
                    }
                    write_block(socket, val);
                    
                } else if (cmd == CMD_ONLINE_WRITE) { // O(1) Online Shift & Inject
                    uint64_t dpf_id;
                    uint64_t c_offset;
                    Block128 V;
                    
                    read_uint64(socket, dpf_id);
                    read_uint64(socket, c_offset);
                    read_block(socket, V);
                    
                    std::cout << "[Server] Received ONLINE write: dpf_id=" << dpf_id 
                              << ", cyclic shift c=" << c_offset << "..." << std::endl;
                    
                    // Pop matching DPF item from pool with automatic desynchronization recovery (Directive 3)
                    ServerPoolItem pool_item;
                    bool found = false;
                    
                    while (offline_pool_.pop(pool_item)) {
                        if (pool_item.dpf_id == dpf_id) {
                            found = true;
                            break;
                        }
                        std::cerr << "[Server] Warning: DPF ID mismatch (popped " << pool_item.dpf_id 
                                  << ", expected " << dpf_id << "). Discarding stale item." << std::endl;
                    }
                    
                    if (!found) {
                        std::cerr << "[Server] Error: Failed to find matching DPF ID " << dpf_id << " in offline pool!" << std::endl;
                        uint8_t ack = 0;
                        boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                        continue;
                    }
                    
                    // O(1) CPU online phase: cyclic shift by public offset c and conditional XOR into DB
                    size_t n = db_.size();
                    {
                        std::lock_guard<std::mutex> lock(db_mutex_);
                        for (size_t j = 0; j < n; ++j) {
                            size_t src_idx = (j >= c_offset) ? (j - c_offset) : (j + n - c_offset);
                            if (pool_item.expanded_vector[src_idx]) {
                                db_[j] ^= V;
                            }
                        }
                    }
                    
                    std::cout << "[Server] Applied ONLINE update (dpf_id=" << dpf_id 
                              << "). Pool remaining: " << offline_pool_.size() << " items." << std::endl;
                    
                    uint8_t ack = 1;
                    boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                }
            }
        } catch (std::exception& e) {
            std::cout << "[Server] Online client disconnected: " << e.what() << std::endl;
        }
    }

    tcp::acceptor acceptor_;
    std::mutex db_mutex_;
    std::vector<Block128> db_;                      // The XOR-shared database
    size_t depth_;                                  // Tree depth (log2 of db_blocks)
    ThreadSafeQueue<ServerPoolItem> offline_pool_;  // Thread-safe pre-computed pool
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: server <port> <db_size_power_of_2_chars>\n";
        return 1;
    }

    short port = std::atoi(argv[1]);
    size_t total_chars = 1ULL << std::atoi(argv[2]);
    size_t db_blocks = std::max(size_t(1), total_chars / 32);

    boost::asio::io_context io_context;
    Server server(io_context, port, db_blocks);

    std::cout << "[Server] Listening on port " << port << " with DB capacity " << total_chars << " chars (" << db_blocks << " blocks)\n";
    io_context.run();

    return 0;
}
