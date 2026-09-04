/*
 * client.cpp
 * 
 * Provides an interactive terminal UI for the client to interact with the 2-party DPF system.
 * Implements 4-bit DNA character packing, pre-computed Cryptographic Pooling (Producer-Consumer)
 * DUORAM 2-phase writes, and an Oblivious Trie wrapper for insert/search.
 */
#include <iostream>
#include <string>
#include <algorithm>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"
#include "pool.hpp"

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

// Helper: Performs a direct read (simulating PIR) over the online channel
uint64_t oblivious_read_internal(tcp::socket& s0_on, tcp::socket& s1_on, size_t index) {
    uint8_t cmd_read = CMD_READ;
    boost::asio::write(s0_on, boost::asio::buffer(&cmd_read, 1));
    boost::asio::write(s1_on, boost::asio::buffer(&cmd_read, 1));
    
    uint64_t target_block_index = index / 32;
    write_uint64(s0_on, target_block_index);
    write_uint64(s1_on, target_block_index);
    
    Block128 val0, val1;
    read_block(s0_on, val0);
    read_block(s1_on, val1);
    
    Block128 val = val0 ^ val1;
    uint64_t bit_shift = (index % 32) * 4;
    
    if (bit_shift < 64) {
        return (_mm_extract_epi64(val.data, 0) >> bit_shift) & 0xF;
    } else {
        return (_mm_extract_epi64(val.data, 1) >> (bit_shift - 64)) & 0xF;
    }
}

// Module 1: The Offline Producer (Background Daemon)
// Runs continuously in a background thread, generating Leafless DPF keys and streaming them to servers.
void offline_dpf_factory(
    tcp::socket& s0_off,
    tcp::socket& s1_off,
    size_t db_blocks,
    size_t block_depth,
    ThreadSafeQueue<ClientPoolItem>& client_pool,
    std::atomic<bool>& stop_factory,
    std::atomic<uint64_t>& next_dpf_id)
{
    while (!stop_factory) {
        // 1. Generate unique sync ID and random dummy index
        uint64_t dpf_id = next_dpf_id++;
        size_t r_index = rand() % db_blocks;
        
        // 2. Generate Leafless DPF keys targeting r_index
        DPFKey k0, k1;
        DPF::generate(r_index, block_depth, k0, k1);
        
        // 3. Push to Client local pool (blocks if queue reaches capacity for backpressure)
        if (!client_pool.push(ClientPoolItem{dpf_id, r_index})) {
            break; // Pool stopped
        }
        
        // 4. Transmit keys to Servers via offline network sockets
        try {
            write_uint64(s0_off, dpf_id);
            write_key(s0_off, k0);
            uint8_t ack0;
            boost::asio::read(s0_off, boost::asio::buffer(&ack0, 1));
            
            write_uint64(s1_off, dpf_id);
            write_key(s1_off, k1);
            uint8_t ack1;
            boost::asio::read(s1_off, boost::asio::buffer(&ack1, 1));
        } catch (...) {
            break; // Socket disconnected or closed
        }
    }
}

// Module 2: The Online Consumer (O(1) Write Execution)
// Consumes one pre-computed item from the pool and sends ONLY the offset c and payload V to the servers.
void oblivious_write_internal(
    tcp::socket& s0_on,
    tcp::socket& s1_on,
    size_t index,
    uint64_t target_bits,
    size_t db_blocks,
    ThreadSafeQueue<ClientPoolItem>& client_pool)
{
    // 1. Consume one pre-computed item from the pool (Blocks on buffer underflow)
    ClientPoolItem pool_item;
    if (!client_pool.pop(pool_item)) {
        throw std::runtime_error("Client offline pool stopped or underflowed!");
    }
    
    // 2. Read-modify-write: compute XOR difference obliviously
    uint64_t existing_bits = oblivious_read_internal(s0_on, s1_on, index);
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
    
    // 3. Compute the Public Cyclic Offset: c = (target_block_index - r_index) % db_blocks
    uint64_t c = (target_block_index + db_blocks - pool_item.r_index) % db_blocks;
    
    // 4. Online Phase: Transmit strictly O(1) data to servers (dpf_id, c, V)
    // Note: The secret random index r is NEVER transmitted over the network.
    uint8_t cmd_on = CMD_ONLINE_WRITE;
    boost::asio::write(s0_on, boost::asio::buffer(&cmd_on, 1));
    boost::asio::write(s1_on, boost::asio::buffer(&cmd_on, 1));
    
    write_uint64(s0_on, pool_item.dpf_id);
    write_uint64(s1_on, pool_item.dpf_id);
    
    write_uint64(s0_on, c);
    write_uint64(s1_on, c);
    
    write_block(s0_on, V);
    write_block(s1_on, V);
    
    uint8_t ack0, ack1;
    boost::asio::read(s0_on, boost::asio::buffer(&ack0, 1));
    boost::asio::read(s1_on, boost::asio::buffer(&ack1, 1));
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: client <host0> <port0> <host1> <port1> <db_size_power_of_2_chars>\n";
        return 1;
    }

    srand(time(NULL));

    try {
        boost::asio::io_context io_context;
        
        tcp::resolver resolver(io_context);
        auto endpoints0 = resolver.resolve(argv[1], argv[2]);
        auto endpoints1 = resolver.resolve(argv[3], argv[4]);
        
        size_t total_chars = 1ULL << std::atoi(argv[5]);
        size_t db_blocks = std::max(size_t(1), total_chars / 32);
        size_t block_depth = __builtin_ctzll(db_blocks); // log2 of blocks
        
        // 1. Establish Offline streaming sockets
        tcp::socket socket0_off(io_context);
        tcp::socket socket1_off(io_context);
        boost::asio::connect(socket0_off, endpoints0);
        boost::asio::connect(socket1_off, endpoints1);
        
        uint8_t role_off = ROLE_OFFLINE;
        boost::asio::write(socket0_off, boost::asio::buffer(&role_off, 1));
        boost::asio::write(socket1_off, boost::asio::buffer(&role_off, 1));
        
        // 2. Establish Online execution sockets
        tcp::socket socket0_on(io_context);
        tcp::socket socket1_on(io_context);
        boost::asio::connect(socket0_on, endpoints0);
        boost::asio::connect(socket1_on, endpoints1);
        
        uint8_t role_on = ROLE_ONLINE;
        boost::asio::write(socket0_on, boost::asio::buffer(&role_on, 1));
        boost::asio::write(socket1_on, boost::asio::buffer(&role_on, 1));
        
        std::cout << "Connected to both servers (Offline & Online channels separated).\n";
        std::cout << "Database holds " << total_chars << " characters (" << db_blocks << " blocks).\n";
        
        // 3. Start the Offline Producer Factory background thread
        ThreadSafeQueue<ClientPoolItem> client_offline_pool(100);
        std::atomic<bool> stop_factory{false};
        std::atomic<uint64_t> next_dpf_id{1};
        
        std::thread factory_thread(
            offline_dpf_factory,
            std::ref(socket0_off),
            std::ref(socket1_off),
            db_blocks,
            block_depth,
            std::ref(client_offline_pool),
            std::ref(stop_factory),
            std::ref(next_dpf_id)
        );
        
        std::cout << "Pre-computed Cryptographic Pooling daemon started in background.\n";
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
                uint64_t raw_bits = oblivious_read_internal(socket0_on, socket1_on, index);
                std::cout << "Read character at index " << index << ": " << bits_to_char(raw_bits) 
                          << " (binary: " << raw_bits << ")\n";
                          
            } else if (cmd == "write") {
                size_t index;
                char c;
                std::cin >> index >> c;
                uint64_t target_bits = char_to_bits(c);
                
                oblivious_write_internal(socket0_on, socket1_on, index, target_bits, db_blocks, client_offline_pool);
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
                    oblivious_write_internal(socket0_on, socket1_on, next_idx, val, db_blocks, client_offline_pool);
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
                    
                    uint64_t read_val = oblivious_read_internal(socket0_on, socket1_on, next_idx);
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
        
        // Graceful shutdown
        stop_factory = true;
        client_offline_pool.stop();
        boost::system::error_code ec;
        socket0_off.close(ec);
        socket1_off.close(ec);
        if (factory_thread.joinable()) {
            factory_thread.join();
        }
        socket0_on.close(ec);
        socket1_on.close(ec);
        
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
