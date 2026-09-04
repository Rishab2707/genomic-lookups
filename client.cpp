/*
 * client.cpp
 * 
 * Provides an interactive terminal UI for the client to interact with the 2-party DPF system.
 * Implements 4-bit DNA character packing, DUORAM 2-phase offline/online writes, 
 * and an Oblivious Trie wrapper for insert/search.
 */
#include <iostream>
#include <string>
#include <algorithm>
#include <cstdlib>
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

// Helper: Performs a direct read (simulating PIR)
uint64_t oblivious_read_internal(tcp::socket& s0, tcp::socket& s1, size_t index) {
    uint8_t cmd_read = 0;
    boost::asio::write(s0, boost::asio::buffer(&cmd_read, 1));
    boost::asio::write(s1, boost::asio::buffer(&cmd_read, 1));
    
    uint64_t target_block_index = index / 32;
    boost::asio::write(s0, boost::asio::buffer(&target_block_index, sizeof(target_block_index)));
    boost::asio::write(s1, boost::asio::buffer(&target_block_index, sizeof(target_block_index)));
    
    Block128 val0, val1;
    read_block(s0, val0);
    read_block(s1, val1);
    
    Block128 val = val0 ^ val1;
    uint64_t bit_shift = (index % 32) * 4;
    
    if (bit_shift < 64) {
        return (_mm_extract_epi64(val.data, 0) >> bit_shift) & 0xF;
    } else {
        return (_mm_extract_epi64(val.data, 1) >> (bit_shift - 64)) & 0xF;
    }
}

// Helper: Performs the DUORAM 2-phase Write Protocol automatically
void oblivious_write_internal(tcp::socket& s0, tcp::socket& s1, size_t index, uint64_t target_bits, size_t db_blocks, size_t block_depth) {
    // 1. OFFLINE PHASE (Client acts as Dealer)
    size_t r_block_index = rand() % db_blocks;
    DPFKey k0, k1;
    DPF::generate(r_block_index, block_depth, k0, k1);
    
    uint8_t cmd_off = 1;
    boost::asio::write(s0, boost::asio::buffer(&cmd_off, 1));
    boost::asio::write(s1, boost::asio::buffer(&cmd_off, 1));
    write_key(s0, k0);
    write_key(s1, k1);
    
    uint8_t ack0, ack1;
    boost::asio::read(s0, boost::asio::buffer(&ack0, 1));
    boost::asio::read(s1, boost::asio::buffer(&ack1, 1));

    // 2. READ-MODIFY-WRITE (Compute XOR difference)
    uint64_t existing_bits = oblivious_read_internal(s0, s1, index);
    uint64_t diff_bits = existing_bits ^ target_bits;
    
    uint64_t target_block_index = index / 32;
    uint64_t bit_shift = (index % 32) * 4;
    
    // Construct the exactly shifted 128-bit XOR payload
    uint64_t p_high = 0, p_low = 0;
    if (bit_shift < 64) {
        p_low = diff_bits << bit_shift;
    } else {
        p_high = diff_bits << (bit_shift - 64);
    }
    Block128 V(p_high, p_low);
    
    // 3. ONLINE PHASE (DUORAM fast shift)
    uint8_t cmd_on = 2;
    boost::asio::write(s0, boost::asio::buffer(&cmd_on, 1));
    boost::asio::write(s1, boost::asio::buffer(&cmd_on, 1));
    
    uint64_t delta = (target_block_index + db_blocks - r_block_index) % db_blocks;
    boost::asio::write(s0, boost::asio::buffer(&delta, sizeof(delta)));
    boost::asio::write(s1, boost::asio::buffer(&delta, sizeof(delta)));
    write_block(s0, V);
    write_block(s1, V);
    
    boost::asio::read(s0, boost::asio::buffer(&ack0, 1));
    boost::asio::read(s1, boost::asio::buffer(&ack1, 1));
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: client <host0> <port0> <host1> <port1> <db_size_power_of_2_chars>\n";
        return 1;
    }

    srand(time(NULL)); // Seed for DUORAM offline random index generation

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
        std::cout << "Available commands: write <index> <char>, read <index>, insert <seq>, search <seq>, exit\n";
        
        while (true) {
            std::cout << "> ";
            std::string cmd;
            if (!(std::cin >> cmd)) break; // Allows EOF (like running from test.txt)
            
            if (cmd == "exit") {
                break;
            } else if (cmd == "read") {
                size_t index;
                std::cin >> index;
                uint64_t raw_bits = oblivious_read_internal(socket0, socket1, index);
                std::cout << "Read character at index " << index << ": " << bits_to_char(raw_bits) 
                          << " (binary: " << raw_bits << ")\n";
                          
            } else if (cmd == "write") {
                size_t index;
                char c;
                std::cin >> index >> c;
                uint64_t target_bits = char_to_bits(c);
                
                oblivious_write_internal(socket0, socket1, index, target_bits, db_blocks, block_depth);
                std::cout << "Write completed obliviously.\n";
                
            } else if (cmd == "insert") {
                std::string seq;
                std::cin >> seq;
                
                size_t curr = 0; // root index
                for (char c : seq) {
                    uint64_t val = char_to_bits(c);
                    size_t char_idx = 0;
                    if (val == 1) char_idx = 1;
                    else if (val == 2) char_idx = 2;
                    else if (val == 4) char_idx = 3;
                    else if (val == 8) char_idx = 4;
                    else continue;
                    
                    // Implicit Complete Trie traversal: child = 4 * curr + char_idx
                    size_t next_idx = 4 * curr + char_idx;
                    
                    // Obliviously write the character to its mathematically assigned node index
                    oblivious_write_internal(socket0, socket1, next_idx, val, db_blocks, block_depth);
                    curr = next_idx;
                }
                std::cout << "Inserted sequence " << seq << " into oblivious trie.\n";
                
            } else if (cmd == "search") {
                std::string seq;
                std::cin >> seq;
                
                size_t curr = 0;
                bool found = true;
                
                // We MUST perform the exact same number of reads regardless of whether we fail 
                // early to prevent side-channel leaks of the sequence length.
                for (char c : seq) {
                    uint64_t val = char_to_bits(c);
                    size_t char_idx = 0;
                    if (val == 1) char_idx = 1;
                    else if (val == 2) char_idx = 2;
                    else if (val == 4) char_idx = 3;
                    else if (val == 8) char_idx = 4;
                    else continue;
                    
                    size_t next_idx = 4 * curr + char_idx;
                    
                    uint64_t read_val = oblivious_read_internal(socket0, socket1, next_idx);
                    if (read_val != val) {
                        found = false;
                        curr = 0; // Reset curr to 0 to safely pad dummy reads without overflowing bounds
                    } else {
                        curr = next_idx;
                    }
                }
                if (found) std::cout << "Sequence " << seq << " FOUND in trie.\n";
                else std::cout << "Sequence " << seq << " NOT FOUND.\n";
                
            } else {
                std::cout << "Unknown command.\n";
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
