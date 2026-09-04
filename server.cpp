/*
 * server.cpp
 * 
 * Implements a standalone background server process acting as one of the 
 * computation parties (P0 or P1) in the networked 2-party system.
 * Implements DUORAM 2-phase offline/online architecture.
 */
#include <iostream>
#include <vector>
#include <algorithm>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"

using boost::asio::ip::tcp;

class Server {
public:
    Server(boost::asio::io_context& io_context, short port, size_t db_blocks)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), db_(db_blocks) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout << "[Server] Client connected." << std::endl;
                    handle_client(std::move(socket));
                }
                do_accept();
            });
    }

    void handle_client(tcp::socket socket) {
        try {
            while (true) {
                uint8_t cmd;
                boost::asio::read(socket, boost::asio::buffer(&cmd, 1));
                
                if (cmd == 0) { // READ (Direct read for secret-shared DB)
                    uint64_t block_index;
                    boost::asio::read(socket, boost::asio::buffer(&block_index, sizeof(block_index)));
                    
                    Block128 val;
                    if (block_index < db_.size()) {
                        val = db_[block_index];
                    }
                    write_block(socket, val);
                    
                } else if (cmd == 1) { // OFFLINE PHASE (Generate Shared Randomness)
                    DPFKey key;
                    read_key(socket, key);
                    
                    std::cout << "[Server] Received OFFLINE key. Evaluating and buffering..." << std::endl;
                    
                    size_t depth = __builtin_ctzll(db_.size()); // log2 of blocks
                    offline_buffer_ = DPF::evaluate_full(key, depth);
                    
                    uint8_t ack = 1;
                    boost::asio::write(socket, boost::asio::buffer(&ack, 1));

                } else if (cmd == 2) { // ONLINE PHASE (DUORAM Shifted Update)
                    if (offline_buffer_.empty() || offline_buffer_.size() != db_.size()) {
                        std::cerr << "[Server] Error: Online write called without valid offline buffer!" << std::endl;
                        uint8_t ack = 0;
                        boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                        continue;
                    }

                    uint64_t delta;
                    Block128 V;
                    boost::asio::read(socket, boost::asio::buffer(&delta, sizeof(delta)));
                    read_block(socket, V);
                    
                    std::cout << "[Server] Received ONLINE update (shift Delta=" << delta << ")..." << std::endl;
                    
                    size_t n = db_.size();
                    // Circularly shift the offline boolean buffer by Delta, conditionally injecting V into DB.
                    for (size_t j = 0; j < n; ++j) {
                        size_t src_idx = (j >= delta) ? (j - delta) : (j + n - delta);
                        if (offline_buffer_[src_idx]) {
                            db_[j] ^= V;
                        }
                    }
                    
                    // Consume the buffer (randomness can only be used once)
                    offline_buffer_.clear();
                    
                    uint8_t ack = 1;
                    boost::asio::write(socket, boost::asio::buffer(&ack, 1));
                }
            }
        } catch (std::exception& e) {
            std::cout << "[Server] Client disconnected: " << e.what() << std::endl;
        }
    }

    tcp::acceptor acceptor_;
    std::vector<Block128> db_; // The XOR-shared database
    std::vector<bool> offline_buffer_; // Holds the Leafless DPF boolean randomness
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
