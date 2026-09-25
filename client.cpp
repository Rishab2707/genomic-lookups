/*
 * client.cpp
 * 
 * Provides a lightweight, thin terminal UI for interacting with the 3-Party DUORAM system.
 * 
 * Key architectural features:
 * 1. Client contains NO cryptographic primitives (DPF key generation, AES-NI PRG, or offline pool management).
 *    All offline randomness is produced by the independent Dealer (dealer.cpp).
 * 2. Client is responsible ONLY for:
 *    - Generating XOR shares of query target indices: t = t0 ^ t1.
 *    - Transmitting t0 to Server 0 and t1 to Server 1 over online channels.
 *    - Receiving secret shares of the result and reconstructing the plaintext (val = val0 ^ val1).
 * 3. Supports DNA 4-bit encoding, Oblivious Trie traversal for insert/search, and point read/write.
 */

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <random>
#include <boost/asio.hpp>
#include "prg.hpp"
#include "network.hpp"

using boost::asio::ip::tcp;

/**
 * @brief Computes the maximum DNA sequence length that fits within the database.
 * 
 * In an implicit complete 4-ary trie, inserting a DNA sequence of length L navigates 
 * through nodes according to: next_idx = 4 * curr + char_idx, where char_idx in {1, 2, 3, 4}.
 * The maximum node index reached at depth L is:
 *   max_idx(L) = sum_{k=1}^L 4^k = (4^(L+1) - 4) / 3.
 * For all sequences of length L to fit within the database, max_idx(L) must be < total_chars.
 * 
 * @param total_chars The total character capacity of the database.
 * @return The maximum supported DNA sequence length.
 */
[[nodiscard]] constexpr size_t compute_max_dna_length(size_t total_chars) noexcept {
    size_t max_len = 0;
    uint64_t max_idx = 0;
    while (true) {
        if (max_idx > (std::numeric_limits<uint64_t>::max() - 4) / 4) {
            break;
        }
        uint64_t next_max_idx = 4 * max_idx + 4;
        if (next_max_idx < total_chars) {
            max_idx = next_max_idx;
            ++max_len;
        } else {
            break;
        }
    }
    return max_len;
}

// Maps a character to its 1-hot 4-bit representation
[[nodiscard]] uint64_t char_to_bits(char c) noexcept {
    if (c == 'A' || c == 'a') return 1; // 0001
    if (c == 'C' || c == 'c') return 2; // 0010
    if (c == 'T' || c == 't') return 4; // 0100
    if (c == 'G' || c == 'g') return 8; // 1000
    return 0;                           // 0000 (NULL or empty)
}

// Maps 4 bits back to the DNA character
[[nodiscard]] char bits_to_char(uint64_t b) noexcept {
    if (b == 1) return 'A';
    if (b == 2) return 'C';
    if (b == 4) return 'T';
    if (b == 8) return 'G';
    return 'N'; // NULL
}

namespace {
    // Secret shares must come from an OS-backed source, not a simulation PRNG.
    std::random_device g_rng;

    Block128 random_block() {
        auto random_word = []() {
            return (uint64_t(g_rng()) << 32) | uint64_t(g_rng());
        };
        return Block128(random_word(), random_word());
    }
}

/**
 * @brief Performs an oblivious read of a 4-bit character at the specified index.
 * 
 * The client splits the target block index into two XOR shares: t = t0 ^ t1.
 * Server 0 receives t0; Server 1 receives t1.
 * Each server evaluates its DPF with XOR permutation, and returns a Block128 share.
 * The client reconstructs val = val0 ^ val1 and extracts the 4-bit character.
 */
uint64_t oblivious_read_internal(tcp::socket& s0_on, tcp::socket& s1_on, size_t index, size_t db_blocks) {
    uint64_t target_block_index = index / 32;
    uint64_t bit_shift = (index % 32) * 4;

    // 1. Generate uniform XOR shares of target block index: t0 in [0, db_blocks - 1], t1 = t ^ t0
    std::uniform_int_distribution<uint64_t> dist(0, db_blocks - 1);
    uint64_t t0 = dist(g_rng);
    uint64_t t1 = target_block_index ^ t0;

    // 2. Transmit CMD_READ and index share to Server 0
    uint8_t cmd_read = CMD_READ;
    boost::asio::write(s0_on, boost::asio::buffer(&cmd_read, 1));
    write_uint64(s0_on, t0);

    // 3. Transmit CMD_READ and index share to Server 1
    boost::asio::write(s1_on, boost::asio::buffer(&cmd_read, 1));
    write_uint64(s1_on, t1);

    // 4. Receive 128-bit shares from both servers
    Block128 val0, val1;
    read_block(s0_on, val0);
    read_block(s1_on, val1);

    // 5. Reconstruct plaintext block
    Block128 val = val0 ^ val1;

    // 6. Extract 4-bit character at bit_shift
    if (bit_shift < 64) {
        return (_mm_extract_epi64(val.data, 0) >> bit_shift) & 0xF;
    } else {
        return (_mm_extract_epi64(val.data, 1) >> (bit_shift - 64)) & 0xF;
    }
}

/**
 * @brief Performs an oblivious write of 4-bit target bits at the specified index.
 * 
 * 1. Performs an oblivious read to retrieve the existing 4 bits.
 * 2. Computes the XOR difference: diff_bits = existing_bits ^ target_bits.
 * 3. Shifts diff_bits to its proper position within the 128-bit block V.
 * 4. Generates uniform XOR shares: t = t0 ^ t1.
 * 5. Sends (CMD_ONLINE_WRITE, t0, V) to Server 0, and (CMD_ONLINE_WRITE, t1, V) to Server 1.
 */
void oblivious_write_internal(tcp::socket& s0_on, tcp::socket& s1_on,
                              size_t index, uint64_t target_bits, size_t db_blocks) {
    // 1. Read existing value obliviously
    uint64_t existing_bits = oblivious_read_internal(s0_on, s1_on, index, db_blocks);
    uint64_t diff_bits = existing_bits ^ target_bits;

    uint64_t target_block_index = index / 32;
    uint64_t bit_shift = (index % 32) * 4;

    // 2. Construct 128-bit XOR update payload V
    uint64_t p_high = 0, p_low = 0;
    if (bit_shift < 64) {
        p_low = diff_bits << bit_shift;
    } else {
        p_high = diff_bits << (bit_shift - 64);
    }
    const Block128 V(p_high, p_low);
    // The database is XOR shared: each server receives an independent share
    // and their XOR equals the one-hot genomic nibble delta.
    const Block128 V0 = random_block();
    const Block128 V1 = V ^ V0;

    // 3. Generate uniform XOR shares: t0 in [0, db_blocks - 1], t1 = t ^ t0
    std::uniform_int_distribution<uint64_t> dist(0, db_blocks - 1);
    uint64_t t0 = dist(g_rng);
    uint64_t t1 = target_block_index ^ t0;

    // 4. Transmit online write command and shares to servers
    uint8_t cmd_on = CMD_ONLINE_WRITE;

    boost::asio::write(s0_on, boost::asio::buffer(&cmd_on, 1));
    write_uint64(s0_on, t0);
    write_block(s0_on, V0);

    boost::asio::write(s1_on, boost::asio::buffer(&cmd_on, 1));
    write_uint64(s1_on, t1);
    write_block(s1_on, V1);

    // 5. Await ACKs from both servers
    uint8_t ack0 = 0, ack1 = 0;
    boost::asio::read(s0_on, boost::asio::buffer(&ack0, 1));
    boost::asio::read(s1_on, boost::asio::buffer(&ack1, 1));

    if (ack0 != 1 || ack1 != 1) {
        std::cerr << "[Client] Warning: Failed to receive successful ACK from servers during write." << std::endl;
    }
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
        size_t max_seq_len = compute_max_dna_length(total_chars);

        // Establish online execution sockets to both servers
        tcp::socket socket0_on(io_context);
        tcp::socket socket1_on(io_context);
        boost::asio::connect(socket0_on, endpoints0);
        boost::asio::connect(socket1_on, endpoints1);

        uint8_t role_on = ROLE_ONLINE;
        boost::asio::write(socket0_on, boost::asio::buffer(&role_on, 1));
        boost::asio::write(socket1_on, boost::asio::buffer(&role_on, 1));

        std::cout << "[Client] Connected to Server 0 and Server 1 (Thin Client mode).\n";
        std::cout << "[Client] Database capacity: " << total_chars << " characters (" 
                  << db_blocks << " blocks).\n";
        std::cout << "[Client] Maximum supported DNA sequence length: " << max_seq_len << " characters.\n";
        std::cout << "Available commands: write <index> <char>, read <index>, insert <seq> (max length: " 
                  << max_seq_len << "), search <seq>, help, exit\n";

        while (true) {
            std::cout << "> ";
            std::string cmd;
            if (!(std::cin >> cmd)) break;

            if (cmd == "exit") {
                break;
            } else if (cmd == "read") {
                size_t index;
                std::cin >> index;
                if (index >= total_chars) {
                    std::cout << "Error: Index " << index << " out of bounds (max: " << (total_chars - 1) << ")\n";
                    continue;
                }
                uint64_t raw_bits = oblivious_read_internal(socket0_on, socket1_on, index, db_blocks);
                std::cout << "Read character at index " << index << ": " << bits_to_char(raw_bits) 
                          << " (binary: " << raw_bits << ")\n";

            } else if (cmd == "write") {
                size_t index;
                char c;
                std::cin >> index >> c;
                if (index >= total_chars) {
                    std::cout << "Error: Index " << index << " out of bounds (max: " << (total_chars - 1) << ")\n";
                    continue;
                }
                uint64_t target_bits = char_to_bits(c);
                oblivious_write_internal(socket0_on, socket1_on, index, target_bits, db_blocks);
                std::cout << "Write completed obliviously.\n";

            } else if (cmd == "insert") {
                std::string seq;
                std::cin >> seq;

                if (seq.empty()) {
                    std::cout << "Error: DNA sequence cannot be empty.\n";
                    continue;
                }

                if (seq.length() > max_seq_len) {
                    std::cout << "Error: Sequence length (" << seq.length() 
                              << ") exceeds maximum insertable length (" 
                              << max_seq_len << ") for DB capacity " 
                              << total_chars << " characters.\n";
                    continue;
                }

                size_t curr = 0; // Root node
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

                    // Obliviously write character to assigned node
                    oblivious_write_internal(socket0_on, socket1_on, next_idx, val, db_blocks);
                    curr = next_idx;
                }
                std::cout << "Inserted sequence " << seq << " into oblivious trie.\n";

            } else if (cmd == "search") {
                std::string seq;
                std::cin >> seq;

                if (seq.empty()) {
                    std::cout << "Error: DNA sequence cannot be empty.\n";
                    continue;
                }

                if (seq.length() > max_seq_len) {
                    std::cout << "Sequence " << seq << " NOT FOUND (length " << seq.length() 
                              << " exceeds maximum supported length of " << max_seq_len << ").\n";
                    continue;
                }

                size_t curr = 0;
                bool found = true;

                // Oblivious access pattern: perform constant number of reads to prevent timing leaks
                for (char c : seq) {
                    uint64_t val = char_to_bits(c);
                    size_t char_idx = 0;
                    if (val == 1) char_idx = 1;
                    else if (val == 2) char_idx = 2;
                    else if (val == 4) char_idx = 3;
                    else if (val == 8) char_idx = 4;
                    else continue;

                    size_t next_idx = 4 * curr + char_idx;

                    uint64_t read_val = oblivious_read_internal(socket0_on, socket1_on, next_idx, db_blocks);
                    if (read_val != val) {
                        found = false;
                        curr = 0; // Pad remaining reads safely at root without leaking position
                    } else {
                        curr = next_idx;
                    }
                }

                if (found) {
                    std::cout << "Sequence " << seq << " FOUND in trie.\n";
                } else {
                    std::cout << "Sequence " << seq << " NOT FOUND.\n";
                }

            } else if (cmd == "help") {
                std::cout << "Available commands: write <index> <char>, read <index>, insert <seq> (max length: " 
                          << max_seq_len << "), search <seq>, help, exit\n";
            } else {
                std::cout << "Unknown command. Type 'help' for available commands.\n";
            }
        }

        boost::system::error_code ec;
        socket0_on.close(ec);
        socket1_on.close(ec);

    } catch (const std::exception& e) {
        std::cerr << "[Client] Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
