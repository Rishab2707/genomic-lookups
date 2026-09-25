/*
 * Computational server P0/P1 for this project's XOR-shared DUORAM variant.
 * P0 and P1 jointly generate three leafless DPF components in preprocessing,
 * assisted by P2-provided Du-Atallah AND triples. Online address correction is
 * an XOR permutation. READ uses P2's cancellation term; UPDATE applies the
 * three value-DPF vectors to the database share, local blind, and cached peer
 * blinded share. The peer database copy is transferred only during INIT.
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
#include <random>
#include <array>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"
#include "pool.hpp"

using boost::asio::ip::tcp;

class Server {
public:
    /**
     * @brief Constructs the server, initialising databases and starting the accept loop.
     *
     * @param io_context  Boost.Asio IO context.
     * @param party_id    0 or 1.
     * @param port        TCP port to listen on.
     * @param peer_host   Hostname of the peer server.
     * @param peer_port   Port of the peer server.
     * @param db_blocks   Number of 128-bit blocks in the database.
     */
    Server(boost::asio::io_context& io_context,
           int party_id,
           short port,
           const std::string& peer_host,
           short peer_port,
           const std::string& helper_host,
           short helper_port,
           size_t db_blocks)
        : io_context_(io_context),
          acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          party_id_(party_id),
          peer_host_(peer_host),
          peer_port_(peer_port),
          helper_host_(helper_host),
          helper_port_(helper_port),
          db_(db_blocks),
          blind_(db_blocks),      // B_b — our blinding array share (filled during ROLE_INIT)
          f_peer_(db_blocks),     // F_peer — peer's masked database (received after ROLE_INIT)
          depth_(__builtin_ctzll(db_blocks)),
          party_pool_(200),
          peer_connected_(false),
          preprocess_peer_connected_(false),
          helper_connected_(false),
          init_done_(false)
    {
        do_accept();

        // Party 1 actively connects to Party 0 as peer; Party 0 waits to accept the peer
        if (party_id_ == 1) {
            connect_to_peer_thread_ = std::thread([this]() {
                connect_to_peer_loop();
            });
        }
        helper_connect_thread_ = std::thread([this]() {
            connect_to_helper_loop();
        });
        if (party_id_ == 1) {
            connect_to_preprocess_thread_ = std::thread([this]() {
                connect_to_preprocess_peer_loop();
            });
        }
    }

    ~Server() {
        if (connect_to_peer_thread_.joinable()) {
            connect_to_peer_thread_.join();
        }
        if (connect_to_preprocess_thread_.joinable()) {
            connect_to_preprocess_thread_.join();
        }
        if (helper_connect_thread_.joinable()) {
            helper_connect_thread_.join();
        }
    }

private:
    void connect_to_helper_loop() {
        while (!helper_connected_) {
            try {
                auto socket = std::make_unique<tcp::socket>(io_context_);
                tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(helper_host_, std::to_string(helper_port_));
                boost::asio::connect(*socket, endpoints);
                const uint8_t role = party_id_ == 0 ? ROLE_HELPER0 : ROLE_HELPER1;
                boost::asio::write(*socket, boost::asio::buffer(&role, 1));
                {
                    std::lock_guard<std::mutex> lock(helper_mutex_);
                    helper_socket_ = std::move(socket);
                    helper_connected_ = true;
                }
                helper_cv_.notify_all();
                std::cout << "[Server " << party_id_ << "] Connected to online helper P2.\n";
                return;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }
    }

    void wait_for_helper() {
        std::unique_lock<std::mutex> lock(helper_mutex_);
        helper_cv_.wait(lock, [this]() {
            return helper_connected_ && helper_socket_ && helper_socket_->is_open();
        });
    }

    Block128 helper_read(uint64_t dpf_id, uint64_t offset_share) {
        wait_for_helper();
        std::lock_guard<std::mutex> lock(helper_mutex_);
        const uint8_t command = CMD_HELPER_READ;
        boost::asio::write(*helper_socket_, boost::asio::buffer(&command, 1));
        write_uint64(*helper_socket_, dpf_id);
        write_uint64(*helper_socket_, offset_share);
        Block128 gamma;
        read_block(*helper_socket_, gamma);
        return gamma;
    }

    void helper_update(uint64_t dpf_id, uint64_t offset_share,
                       const Block128& final_blind0,
                       const Block128& final_blind1) {
        wait_for_helper();
        std::lock_guard<std::mutex> lock(helper_mutex_);
        const uint8_t command = CMD_HELPER_UPDATE;
        boost::asio::write(*helper_socket_, boost::asio::buffer(&command, 1));
        write_uint64(*helper_socket_, dpf_id);
        write_uint64(*helper_socket_, offset_share);
        write_block(*helper_socket_, final_blind0);
        write_block(*helper_socket_, final_blind1);
        uint8_t ack = 0;
        boost::asio::read(*helper_socket_, boost::asio::buffer(&ack, 1));
        if (ack != 1) throw std::runtime_error("P2 rejected DUORAM update");
    }

    // -------------------------------------------------------------------------
    // Connection dispatch
    // -------------------------------------------------------------------------

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

    /**
     * @brief Reads the role byte from a new connection and routes it appropriately.
     */
    void dispatch_connection(tcp::socket socket) {
        try {
            uint8_t role = 0;
            boost::asio::read(socket, boost::asio::buffer(&role, 1));

            if (role == ROLE_INIT) {
                handle_init(std::move(socket));
            } else if (role == ROLE_OFFLINE) {
                handle_offline_producer(std::move(socket));
            } else if (role == ROLE_ONLINE) {
                handle_online_client(std::move(socket));
            } else if (role == ROLE_PEER) {
                handle_peer_server(std::move(socket), false);
            } else if (role == ROLE_PREPROCESS_PEER) {
                handle_peer_server(std::move(socket), true);
            } else {
                std::cerr << "[Server " << party_id_ << "] Unknown role: " << int(role) << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[Server " << party_id_ << "] Dispatch error: " << e.what() << std::endl;
        }
    }

    // -------------------------------------------------------------------------
    // Peer connection management
    // -------------------------------------------------------------------------

    /** @brief Party 1 active-connect loop: retries until Party 0 peer channel is up. */
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
                std::cout << "[Server " << party_id_ << "] Connected to peer Server 0." << std::endl;
                break;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }
    }

    void connect_to_preprocess_peer_loop() {
        while (!preprocess_peer_connected_) {
            try {
                auto socket = std::make_unique<tcp::socket>(io_context_);
                tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(peer_host_, std::to_string(peer_port_));
                boost::asio::connect(*socket, endpoints);
                const uint8_t role = ROLE_PREPROCESS_PEER;
                boost::asio::write(*socket, boost::asio::buffer(&role, 1));
                {
                    std::lock_guard<std::mutex> lock(preprocess_peer_mutex_);
                    preprocess_peer_socket_ = std::move(socket);
                    preprocess_peer_connected_ = true;
                }
                preprocess_peer_cv_.notify_all();
                return;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }
    }

    /** @brief Party 0 passive handler: stores the accepted peer socket. */
    void handle_peer_server(tcp::socket socket, bool preprocessing) {
        if (preprocessing) {
            {
                std::lock_guard<std::mutex> lock(preprocess_peer_mutex_);
                preprocess_peer_socket_ = std::make_unique<tcp::socket>(std::move(socket));
                preprocess_peer_connected_ = true;
            }
            preprocess_peer_cv_.notify_all();
            return;
        }
        {
            std::lock_guard<std::mutex> lock(peer_mutex_);
            peer_socket_ = std::make_unique<tcp::socket>(std::move(socket));
            peer_connected_ = true;
        }
        peer_cv_.notify_all();
        std::cout << "[Server " << party_id_ << "] Peer Server 1 connected." << std::endl;
    }

    void wait_for_peer() {
        std::unique_lock<std::mutex> lock(peer_mutex_);
        peer_cv_.wait(lock, [this]() {
            return peer_connected_ && peer_socket_ && peer_socket_->is_open();
        });
    }

    void wait_for_preprocess_peer() {
        std::unique_lock<std::mutex> lock(preprocess_peer_mutex_);
        preprocess_peer_cv_.wait(lock, [this]() {
            return preprocess_peer_connected_ && preprocess_peer_socket_ &&
                   preprocess_peer_socket_->is_open();
        });
    }

    Block128 exchange_preprocess_peer_block(const Block128& mine) {
        wait_for_preprocess_peer();
        std::lock_guard<std::mutex> lock(preprocess_peer_mutex_);
        Block128 other;
        if (party_id_ == 0) {
            write_block(*preprocess_peer_socket_, mine);
            read_block(*preprocess_peer_socket_, other);
        } else {
            read_block(*preprocess_peer_socket_, other);
            write_block(*preprocess_peer_socket_, mine);
        }
        return other;
    }

    Block128 exchange_preprocess_block(const Block128& mine) {
        return mine ^ exchange_preprocess_peer_block(mine);
    }

    bool exchange_preprocess_bit(bool mine) {
        const uint64_t local = mine ? 1 : 0;
        uint64_t peer = 0;
        wait_for_preprocess_peer();
        std::lock_guard<std::mutex> lock(preprocess_peer_mutex_);
        if (party_id_ == 0) {
            write_uint64(*preprocess_peer_socket_, local);
            read_uint64(*preprocess_peer_socket_, peer);
        } else {
            read_uint64(*preprocess_peer_socket_, peer);
            write_uint64(*preprocess_peer_socket_, local);
        }
        return ((local ^ peer) & 1U) != 0;
    }

    // -------------------------------------------------------------------------
    // O(1) peer scalar exchange helpers
    // -------------------------------------------------------------------------

    /**
     * @brief Exchanges a single uint64 share with the peer server. Returns reconstructed XOR.
     *
     * Party 0 writes first then reads; Party 1 reads first then writes, to avoid deadlock.
     * @param my_share  This party's additive XOR share.
     * @return          The XOR of both shares: my_share ^ peer_share.
     */
    uint64_t exchange_scalar(uint64_t my_share) {
        wait_for_peer();
        std::lock_guard<std::mutex> lock(peer_mutex_);
        uint64_t other = 0;
        if (party_id_ == 0) {
            write_uint64(*peer_socket_, my_share);
            read_uint64(*peer_socket_, other);
        } else {
            read_uint64(*peer_socket_, other);
            write_uint64(*peer_socket_, my_share);
        }
        return my_share ^ other;
    }

    /**
     * @brief Exchanges a single 128-bit block share with the peer. Returns XOR of both.
     * @param my_block  This party's share.
     * @return          my_block ^ peer_block.
     */
    Block128 exchange_block(const Block128& my_block) {
        wait_for_peer();
        std::lock_guard<std::mutex> lock(peer_mutex_);
        Block128 other;
        if (party_id_ == 0) {
            write_block(*peer_socket_, my_block);
            read_block(*peer_socket_, other);
        } else {
            read_block(*peer_socket_, other);
            write_block(*peer_socket_, my_block);
        }
        return my_block ^ other;
    }

    // -------------------------------------------------------------------------
    // ROLE_INIT: One-shot startup blinding array exchange
    // -------------------------------------------------------------------------

    /**
     * @brief Receives this server's blinding array share B_b from the Dealer, then
     *        exchanges the masked database F_b = D_b ^ B_b with the peer server.
     *
     * This is the ONLY O(N) network transfer in the lifetime of the server. After this
     * completes, all subsequent operations are O(1) network.
     *
     * @param socket  ROLE_INIT socket connected to the Dealer.
     */
    void handle_init(tcp::socket socket) {
        try {
            std::cout << "[Server " << party_id_ << "] INIT: Receiving blinding array B_"
                      << party_id_ << " from Dealer..." << std::endl;

            // Receive B_b from Dealer
            uint64_t count = 0;
            read_uint64(socket, count);
            {
                std::lock_guard<std::mutex> lock(db_mutex_);
                blind_.resize(count);
                boost::asio::read(socket,
                    boost::asio::buffer(blind_.data(), count * sizeof(Block128)));
            }

            // Wait until the peer channel is established before F-exchange
            wait_for_peer();

            // Compute F_b = D_b ^ B_b locally
            std::vector<Block128> my_f(db_.size());
            {
                std::lock_guard<std::mutex> lock(db_mutex_);
                for (size_t i = 0; i < db_.size(); ++i) {
                    my_f[i] = db_[i] ^ blind_[i];
                }
            }

            // Exchange F arrays with peer (only O(N) transfer in online lifetime)
            {
                wait_for_peer();
                std::lock_guard<std::mutex> lock(peer_mutex_);
                if (party_id_ == 0) {
                    write_blocks(*peer_socket_, my_f);
                    read_blocks(*peer_socket_, f_peer_);
                } else {
                    read_blocks(*peer_socket_, f_peer_);
                    write_blocks(*peer_socket_, my_f);
                }
            }

            {
                std::lock_guard<std::mutex> lock(init_mutex_);
                init_done_ = true;
            }
            init_cv_.notify_all();

            // ACK the Dealer to signal F-exchange complete
            uint8_t ack = 1;
            boost::asio::write(socket, boost::asio::buffer(&ack, 1));

            std::cout << "[Server " << party_id_ << "] INIT complete. F_peer loaded ("
                      << f_peer_.size() << " blocks)." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[Server " << party_id_ << "] INIT error: " << e.what() << std::endl;
        }
    }

    void wait_for_init() {
        std::unique_lock<std::mutex> lock(init_mutex_);
        init_cv_.wait(lock, [this]() { return init_done_; });
    }

    // -------------------------------------------------------------------------
    // ROLE_OFFLINE: Dealer streaming pool items
    // -------------------------------------------------------------------------

    // P2 sends only random Beaver shares. P0/P1 choose their own shares of the
    // dummy index and jointly construct three DPFs; no target share is sent to P2.
    void handle_offline_producer(tcp::socket socket) {
        try {
            std::cout << "[Server " << party_id_ << "] P2 triple stream connected." << std::endl;
            std::random_device index_rng;
            std::uniform_int_distribution<uint64_t> index_dist(0, db_.size() - 1);
            while (true) {
                DuoramPartyPoolItem item;
                read_uint64(socket, item.dpf_id);
                item.material.random_index_share = index_dist(index_rng);

                const size_t triple_count = 6 * depth_;
                std::vector<duoram::BeaverAndTripleShare> triples(triple_count);
                for (auto& triple : triples) read_and_triple(socket, triple);
                size_t triple_cursor = 0;

                for (size_t component = 0; component < 3; ++component) {
                    DPFKey key = DPF::generate_shared(
                        party_id_, item.material.random_index_share, depth_,
                        [this, &triples, &triple_cursor](const Block128& a,
                                                        const Block128& b) {
                            if (triple_cursor >= triples.size()) {
                                throw std::runtime_error("P2 Beaver triple stream underflow");
                            }
                            const auto& triple = triples[triple_cursor++];
                            return duoram::du_atallah_and_share(
                                party_id_, a, b, triple,
                                [this](const Block128& share) {
                                    return exchange_preprocess_peer_block(share);
                                });
                        },
                        [this](const Block128& share) {
                            return exchange_preprocess_block(share);
                        },
                        [this](bool share) {
                            return exchange_preprocess_bit(share);
                        });
                    item.material.dpf[component] = duoram::make_dpf_share(
                        DPF::evaluate_full_values(key, depth_));

                    // P2 needs the designated key shares to compute gamma and
                    // refresh its blind copies. The random target remains
                    // shared by P0/P1 and is never included in this message.
                    if ((party_id_ == 0 && component == 1) ||
                        (party_id_ == 1 && component == 2)) {
                        write_key(socket, key);
                    }
                }

                if (triple_cursor != triples.size()) {
                    throw std::runtime_error("unused P2 Beaver triples in DPF generation");
                }

                if (!party_pool_.push(std::move(item))) break;

                uint8_t ack = 1;
                boost::asio::write(socket, boost::asio::buffer(&ack, 1));
            }
        } catch (const std::exception& e) {
            std::cout << "[Server " << party_id_ << "] P2 triple stream disconnected: "
                      << e.what() << std::endl;
        }
    }

    // -------------------------------------------------------------------------
    // ROLE_ONLINE: Client queries
    // -------------------------------------------------------------------------

    /**
     * @brief Main online handler: serves read and write commands from the client.
     *
     * Blocks until INIT is complete before processing any query, guaranteeing that
     * F_peer and blind_ are populated before any dot-product computation.
     *
     * @param socket  ROLE_ONLINE socket connected to the client.
     */
    void handle_online_client(tcp::socket socket) {
        try {
            std::cout << "[Server " << party_id_ << "] Online client connected." << std::endl;

            // Wait for INIT (blinding arrays + F exchange) to be done
            wait_for_init();

            while (true) {
                uint8_t cmd = 0;
                boost::asio::read(socket, boost::asio::buffer(&cmd, 1));

                if (cmd == CMD_READ) {
                    handle_read(socket);
                } else if (cmd == CMD_ONLINE_WRITE) {
                    handle_write(socket);
                }
            }
        } catch (const std::exception& e) {
            std::cout << "[Server " << party_id_ << "] Online client disconnected: "
                      << e.what() << std::endl;
        }
    }

    // -------------------------------------------------------------------------
    // Three-party DUORAM read
    // -------------------------------------------------------------------------

    // Evaluates the paper's three-component read using XOR-share arithmetic.
    // READ consumes preprocessing but leaves the blinds unchanged; UPDATE
    // applies the corresponding blind-refresh vectors.
    void handle_read(tcp::socket& socket) {
        uint64_t t_share = 0;
        read_uint64(socket, t_share);

        DuoramPartyPoolItem pool_item;
        if (!party_pool_.pop(pool_item)) {
            std::cerr << "[Server " << party_id_ << "] DUORAM preprocessing pool stopped." << std::endl;
            Block128 zero;
            write_block(socket, zero);
            return;
        }

        // The online address and the preprocessing address are both XOR
        // shares. Their XOR is a uniform public permutation offset, not the
        // requested index. Apply that same offset to every DPF component.
        const uint64_t offset_share = t_share ^ pool_item.material.random_index_share;
        const uint64_t offset = exchange_scalar(offset_share);
        auto shifted_flags = [offset](const duoram::DpfShare& dpf) {
            return duoram::xor_permute<uint8_t>(dpf.flags, offset);
        };
        const auto& material = pool_item.material;
        const auto t_read = shifted_flags(material.dpf[0]);
        const Block128 gamma = helper_read(pool_item.dpf_id, offset_share);
        Block128 result;
        {
            std::lock_guard<std::mutex> lock(db_mutex_);
            if (party_id_ == 0) {
                const auto t_blind = shifted_flags(material.dpf[2]);
                result = duoram::read_party0(db_, f_peer_, blind_, t_read,
                                             t_blind, gamma);
            } else {
                const auto t_blind = shifted_flags(material.dpf[1]);
                result = duoram::read_party1(db_, f_peer_, blind_, t_read,
                                             t_blind, gamma);
            }
        }

        // A READ does not refresh DUORAM's blinds; only UPDATE performs the
        // blind-refresh equations. The helper's cancellation term is returned
        // as part of the same constant-size online exchange.
        write_block(socket, result);
    }

    // -------------------------------------------------------------------------
    // Three-party DUORAM update / blind refresh
    // -------------------------------------------------------------------------

    /**
     * @brief Handles a single oblivious write using the XOR-permutation and RefreshBlinds.
     *
     * The write XORs the new value V into the database at the target index t.
     * Since both servers hold XOR shares of V (V = V0 ^ V1 from the client), each
     * applies V to its share at the permuted position.
     *
     * After the write, the blind at the target index is refreshed to restore the invariant.
     *
     * @param socket  Client's ROLE_ONLINE socket.
     */
    void handle_write(tcp::socket& socket) {
        uint64_t t_share = 0;
        read_uint64(socket, t_share);

        Block128 value_share;
        read_block(socket, value_share);

        DuoramPartyPoolItem pool_item;
        if (!party_pool_.pop(pool_item)) {
            std::cerr << "[Server " << party_id_ << "] DUORAM preprocessing pool stopped." << std::endl;
            uint8_t ack = 0;
            boost::asio::write(socket, boost::asio::buffer(&ack, 1));
            return;
        }

        const uint64_t offset_share = t_share ^ pool_item.material.random_index_share;
        const uint64_t offset = exchange_scalar(offset_share);

        // The parties open only masked final correction words. For component
        // k, F_k = M_0 + F_(k)_0 + M_1 + F_(k)_1 (addition is XOR here).
        std::array<Block128, 3> final_words{};
        for (size_t k = 0; k < final_words.size(); ++k) {
            final_words[k] = exchange_block(
                value_share ^ pool_item.material.dpf[k].final_correction);
        }

        std::array<duoram::WordVector, 3> corrected;
        for (size_t k = 0; k < corrected.size(); ++k) {
            const auto flags = duoram::xor_permute<uint8_t>(
                pool_item.material.dpf[k].flags, offset);
            const auto values = duoram::xor_permute<Block128>(
                pool_item.material.dpf[k].values, offset);
            corrected[k] = duoram::corrected_update_vector(
                values, flags, final_words[k]);
        }

        // UPDATE (and only UPDATE) refreshes the blinds and the peer's cached
        // blinded database share. Subtraction and addition coincide over the
        // project's XOR-shared word representation.
        {
            std::lock_guard<std::mutex> lock(db_mutex_);
            for (size_t i = 0; i < db_.size(); ++i) {
                db_[i] ^= corrected[0][i];
                if (party_id_ == 0) {
                    blind_[i] ^= corrected[1][i];
                    f_peer_[i] ^= corrected[2][i] ^ corrected[0][i];
                } else {
                    blind_[i] ^= corrected[2][i];
                    f_peer_[i] ^= corrected[1][i] ^ corrected[0][i];
                }
            }
        }

        // P2 uses the same two final correction words to refresh its blind
        // copies. Both P0 and P1 send their masked address share.
        helper_update(pool_item.dpf_id, offset_share, final_words[1], final_words[2]);

        uint8_t ack = 1;
        boost::asio::write(socket, boost::asio::buffer(&ack, 1));
    }

    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    int party_id_;
    std::string peer_host_;
    short peer_port_;
    std::string helper_host_;
    short helper_port_;

    mutable std::mutex db_mutex_;
    std::vector<Block128> db_;      // D_b: XOR share of the true database
    std::vector<Block128> blind_;   // B_b: XOR share of the blinding array (set by Dealer at INIT)
    std::vector<Block128> f_peer_;  // F_peer: peer's masked database, maintained by blind refresh updates
    size_t depth_;

    ThreadSafeQueue<DuoramPartyPoolItem> party_pool_;

    std::mutex peer_mutex_;
    std::condition_variable peer_cv_;
    std::unique_ptr<tcp::socket> peer_socket_;
    bool peer_connected_;
    std::thread connect_to_peer_thread_;

    std::mutex preprocess_peer_mutex_;
    std::condition_variable preprocess_peer_cv_;
    std::unique_ptr<tcp::socket> preprocess_peer_socket_;
    bool preprocess_peer_connected_ = false;
    std::thread connect_to_preprocess_thread_;

    std::mutex helper_mutex_;
    std::condition_variable helper_cv_;
    std::unique_ptr<tcp::socket> helper_socket_;
    bool helper_connected_;
    std::thread helper_connect_thread_;

    std::mutex init_mutex_;
    std::condition_variable init_cv_;
    bool init_done_;
};

int main(int argc, char* argv[]) {
    int party_id = 0;
    short port = 8000;
    std::string peer_host = "127.0.0.1";
    short peer_port = 8001;
    std::string helper_host = "127.0.0.1";
    short helper_port = 8002;
    size_t total_chars = 1024;

    if (argc == 6 || argc == 8) {
        party_id   = std::atoi(argv[1]);
        port       = std::atoi(argv[2]);
        peer_host  = argv[3];
        peer_port  = std::atoi(argv[4]);
        total_chars = 1ULL << std::atoi(argv[5]);
        if (argc == 8) {
            helper_host = argv[6];
            helper_port = std::atoi(argv[7]);
        }
    } else if (argc == 3) {
        port        = std::atoi(argv[1]);
        total_chars = 1ULL << std::atoi(argv[2]);
        if (port == 8000) {
            party_id = 0; peer_host = "127.0.0.1"; peer_port = 8001;
        } else {
            party_id = 1; peer_host = "127.0.0.1"; peer_port = 8000;
        }
    } else {
        std::cerr << "Usage: server <party_id> <port> <peer_host> <peer_port> <db_size_power_of_2_chars>\n"
                  << "  Or:  server <port> <db_size_power_of_2_chars>\n";
        return 1;
    }

    size_t db_blocks = std::max(size_t(1), total_chars / 32);

    boost::asio::io_context io_context;
    Server server(io_context, party_id, port, peer_host, peer_port,
                  helper_host, helper_port, db_blocks);

    std::cout << "[Server " << party_id << "] Listening on port " << port
              << " (Peer: " << peer_host << ":" << peer_port << ")"
              << " DB: " << total_chars << " chars (" << db_blocks << " blocks)\n";

    io_context.run();
    return 0;
}
