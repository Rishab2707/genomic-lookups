/*
 * server.cpp
 * 
 * Implements a standalone background server process acting as one of the 
 * computation parties (P0 or P1) in the networked 2-party system.
 * Listens for TCP connections from the client and evaluates DPF keys obliviously.
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
    // Initializes the server on a specific TCP port and allocates the shared database
    Server(boost::asio::io_context& io_context, short port, size_t db_blocks)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), db_(db_blocks) {
        
        // The database is initialized to zero (or random XOR shares in a production setup)
        do_accept();
    }

private:
    // Asynchronously accepts incoming TCP connections from clients
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout << "[Server] Client connected." << std::endl;
                    // Processes the client connection synchronously (in this demo)
                    handle_client(std::move(socket));
                }
                do_accept();
            });
    }

    // Handles the protocol exchange for a connected client
    void handle_client(tcp::socket socket) {
        try {
            while (true) {
                uint8_t cmd;
                // Wait for the client to send a command byte (0 = READ, 1 = WRITE)
                boost::asio::read(socket, boost::asio::buffer(&cmd, 1));
                
                if (cmd == 0) { // READ (Direct read for secret-shared DB)
                    uint64_t block_index;
                    boost::asio::read(socket, boost::asio::buffer(&block_index, sizeof(block_index)));
                    std::cout << "[Server] Received READ request for block " << block_index << std::endl;
                    
                    Block128 val;
                    if (block_index < db_.size()) {
                        val = db_[block_index];
                    }
                    
                    // Return the entire 128-bit block so the client can extract the character nibble
                    write_block(socket, val);
                    
                } else if (cmd == 1) { // WRITE (Oblivious Update)
                    DPFKey key;
                    read_key(socket, key);
                    
                    std::cout << "[Server] Received WRITE key. Evaluating and updating DB..." << std::endl;
                    
                    // Evaluate the DPF key. The resulting vector contains XOR shares of the payload 
                    // at the target index, and XOR shares of 0 everywhere else.
                    size_t depth = __builtin_ctzll(db_.size()); // log2 of blocks
                    auto vec = DPF::evaluate_full(key, depth);
                    
                    // Obliviously apply the update to the entire database without learning the target block index.
                    for (size_t i = 0; i < db_.size(); ++i) {
                        db_[i] ^= vec[i];
                    }
                    
                    // Send an acknowledgment byte back to the client
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
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: server <port> <db_size_power_of_2_chars>\n";
        return 1;
    }

    short port = std::atoi(argv[1]);
    size_t total_chars = 1ULL << std::atoi(argv[2]);
    
    // We pack 32 characters (4 bits each) into a 128-bit block
    size_t db_blocks = std::max(size_t(1), total_chars / 32);

    boost::asio::io_context io_context;
    Server server(io_context, port, db_blocks);

    std::cout << "[Server] Listening on port " << port << " with DB capacity " << total_chars << " chars (" << db_blocks << " blocks)\n";
    io_context.run(); // Start the asynchronous Boost.Asio event loop

    return 0;
}
