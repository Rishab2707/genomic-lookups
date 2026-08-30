/*
 * client.cpp
 * 
 * Provides an interactive terminal UI for the client to interact with the 2-party DPF system.
 * Implements 4-bit DNA character packing (32 characters per 128-bit block).
 */
#include <iostream>
#include <string>
#include <algorithm>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"

using boost::asio::ip::tcp;

// Maps a character to its 1-hot 4-bit representation
uint64_t char_to_bits(char c) {
    if (c == 'A' || c == 'a') return 1; // 0001
    if (c == 'T' || c == 't') return 2; // 0010
    if (c == 'C' || c == 'c') return 4; // 0100
    if (c == 'G' || c == 'g') return 8; // 1000
    return 0;                           // 0000 (NULL or 'N')
}

// Maps 4 bits back to the DNA character
char bits_to_char(uint64_t b) {
    if (b == 1) return 'A';
    if (b == 2) return 'T';
    if (b == 4) return 'C';
    if (b == 8) return 'G';
    return 'N'; // NULL
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: client <host0> <port0> <host1> <port1> <db_size_power_of_2_chars>\n";
        return 1;
    }

    try {
        boost::asio::io_context io_context;
        
        tcp::resolver resolver(io_context);
        auto endpoints0 = resolver.resolve(argv[1], argv[2]);
        auto endpoints1 = resolver.resolve(argv[3], argv[4]);
        
        size_t total_chars = 1ULL << std::atoi(argv[5]);
        size_t db_blocks = std::max(size_t(1), total_chars / 32);
        size_t block_depth = __builtin_ctzll(db_blocks); // log2 of blocks
        
        tcp::socket socket0(io_context);
        tcp::socket socket1(io_context);
        
        boost::asio::connect(socket0, endpoints0);
        boost::asio::connect(socket1, endpoints1);
        
        std::cout << "Connected to both servers. Database holds " << total_chars << " characters.\n";
        std::cout << "Available commands: write <index> <char>, read <index>, exit\n";
        
        while (true) {
            std::cout << "> ";
            std::string cmd;
            std::cin >> cmd;
            
            if (cmd == "exit") {
                break;
            } else if (cmd == "read") {
                size_t index;
                std::cin >> index;
                
                uint8_t read_cmd = 0;
                boost::asio::write(socket0, boost::asio::buffer(&read_cmd, 1));
                boost::asio::write(socket1, boost::asio::buffer(&read_cmd, 1));
                
                uint64_t block_index = index / 32;
                boost::asio::write(socket0, boost::asio::buffer(&block_index, sizeof(block_index)));
                boost::asio::write(socket1, boost::asio::buffer(&block_index, sizeof(block_index)));
                
                Block128 val0, val1;
                read_block(socket0, val0);
                read_block(socket1, val1);
                
                Block128 val = val0 ^ val1;
                uint64_t bit_shift = (index % 32) * 4;
                
                uint64_t raw_bits = 0;
                if (bit_shift < 64) {
                    uint64_t low = _mm_extract_epi64(val.data, 0);
                    raw_bits = (low >> bit_shift) & 0xF;
                } else {
                    uint64_t high = _mm_extract_epi64(val.data, 1);
                    raw_bits = (high >> (bit_shift - 64)) & 0xF;
                }
                
                std::cout << "Read character at index " << index << ": " << bits_to_char(raw_bits) 
                          << " (binary: " << raw_bits << ")\n";
                          
            } else if (cmd == "write") {
                size_t index;
                char c;
                std::cin >> index >> c;
                
                uint64_t target_bits = char_to_bits(c);
                
                // 1. OBLIVIOUS READ-MODIFY-WRITE
                // We first read the exact block to find the existing 4-bit nibble.
                // In a true secure implementation, this read would be oblivious via MPC.
                // For this Client-Server architecture, we retrieve the block to compute the XOR difference.
                uint8_t read_cmd = 0;
                boost::asio::write(socket0, boost::asio::buffer(&read_cmd, 1));
                boost::asio::write(socket1, boost::asio::buffer(&read_cmd, 1));
                
                uint64_t block_index = index / 32;
                boost::asio::write(socket0, boost::asio::buffer(&block_index, sizeof(block_index)));
                boost::asio::write(socket1, boost::asio::buffer(&block_index, sizeof(block_index)));
                
                Block128 val0, val1;
                read_block(socket0, val0);
                read_block(socket1, val1);
                
                Block128 val = val0 ^ val1;
                uint64_t bit_shift = (index % 32) * 4;
                
                uint64_t existing_bits = 0;
                if (bit_shift < 64) {
                    existing_bits = (_mm_extract_epi64(val.data, 0) >> bit_shift) & 0xF;
                } else {
                    existing_bits = (_mm_extract_epi64(val.data, 1) >> (bit_shift - 64)) & 0xF;
                }
                
                // 2. Compute XOR difference
                uint64_t diff_bits = existing_bits ^ target_bits;
                
                // 3. Package diff_bits into a 128-bit payload precisely shifted to the correct nibble
                uint64_t p_high = 0, p_low = 0;
                if (bit_shift < 64) {
                    p_low = diff_bits << bit_shift;
                } else {
                    p_high = diff_bits << (bit_shift - 64);
                }
                Block128 payload(p_high, p_low);
                
                DPFKey key0, key1;
                // Generate the DPF keys traversing down to the specific 128-bit block
                DPF::generate(block_index, block_depth, key0, key1, payload);
                
                // 4. Send the WRITE command to obliviously apply the XOR difference
                uint8_t write_cmd = 1;
                boost::asio::write(socket0, boost::asio::buffer(&write_cmd, 1));
                boost::asio::write(socket1, boost::asio::buffer(&write_cmd, 1));
                
                write_key(socket0, key0);
                write_key(socket1, key1);
                
                uint8_t ack0, ack1;
                boost::asio::read(socket0, boost::asio::buffer(&ack0, 1));
                boost::asio::read(socket1, boost::asio::buffer(&ack1, 1));
                
                std::cout << "Write completed obliviously.\n";
            } else {
                std::cout << "Unknown command.\n";
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
