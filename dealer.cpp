/*
 * dealer.cpp
 * 
 * Standalone offline Dealer for the 3-Party Distributed ORAM (DUORAM) architecture.
 * 
 * Responsibilities:
 * 1. Operates continuously as a background daemon, unaware of any client query target indices.
 * 2. Employs a Two-Phase replenishment strategy:
 *    - Phase 1 (Warmup): Rapidly pre-generates an initial buffer of keys (default: 100) with 0ms delay.
 *    - Phase 2 (Paced Idle): Supplies random DPF keys at a controlled cadence (default: 100ms interval)
 *      during server idle time, drawing minimal CPU while keeping server queues saturated.
 * 3. Splits each dummy index r into uniform XOR secret shares: r = r0 ^ r1.
 * 4. Generates Boyle-Gilboa-Ishai (BGI) Distributed Point Function (DPF) keys (k0, k1) targeting r.
 * 5. Streams (dpf_id, r0, k0) to Server 0 and (dpf_id, r1, k1) to Server 1 over their
 *    dedicated offline TCP channels, respecting TCP queue backpressure.
 */

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <boost/asio.hpp>
#include "dpf.hpp"
#include "network.hpp"
#include "pool.hpp"

using boost::asio::ip::tcp;

namespace {
    std::atomic<bool> g_stop_requested{false};

    void signal_handler(int) {
        g_stop_requested.store(true);
    }
}

/**
 * @brief Standalone offline Dealer class to produce correlated randomness for Server 0 and Server 1.
 */
class Dealer {
public:
    Dealer(boost::asio::io_context& io_context,
           const std::string& host0, const std::string& port0,
           const std::string& host1, const std::string& port1,
           size_t db_blocks, size_t block_depth)
        : io_context_(io_context),
          socket0_(io_context),
          socket1_(io_context),
          db_blocks_(db_blocks),
          block_depth_(block_depth),
          rng_(std::random_device{}()),
          dist_(0, db_blocks - 1)
    {
        tcp::resolver resolver(io_context_);
        auto endpoints0 = resolver.resolve(host0, port0);
        auto endpoints1 = resolver.resolve(host1, port1);

        std::cout << "[Dealer] Connecting to Server 0 (" << host0 << ":" << port0 << ")..." << std::endl;
        boost::asio::connect(socket0_, endpoints0);
        std::cout << "[Dealer] Connecting to Server 1 (" << host1 << ":" << port1 << ")..." << std::endl;
        boost::asio::connect(socket1_, endpoints1);

        // Perform offline role handshake
        uint8_t role = ROLE_OFFLINE;
        boost::asio::write(socket0_, boost::asio::buffer(&role, 1));
        boost::asio::write(socket1_, boost::asio::buffer(&role, 1));

        std::cout << "[Dealer] Successfully connected to both servers via offline channels." << std::endl;
    }

    /**
     * @brief Runs the two-phase offline DPF generation daemon.
     * 
     * @param target_count Total items to generate (0 means continuous background daemon).
     * @param warmup_count Number of keys to burst-generate immediately at startup (0ms delay).
     * @param interval_ms Sleep duration between generations in steady-state idle phase.
     */
    void run(int64_t target_count = 0, int64_t warmup_count = 100, int64_t interval_ms = 100) {
        uint64_t dpf_id = 1;
        int64_t generated_count = 0;
        bool warmup_completed = false;

        if (target_count > 0) {
            std::cout << "[Dealer] Running in finite batch mode (target=" << target_count 
                      << " items, warmup=" << warmup_count 
                      << " items, idle_interval=" << interval_ms << "ms)..." << std::endl;
        } else {
            std::cout << "[Dealer] Running as persistent background daemon (warmup=" << warmup_count 
                      << " items, idle_interval=" << interval_ms << "ms)..." << std::endl;
        }

        while (!g_stop_requested.load()) {
            if (target_count > 0 && generated_count >= target_count) {
                std::cout << "[Dealer] Target count of " << target_count << " items reached. Stopping." << std::endl;
                break;
            }

            // Phase transition check
            if (!warmup_completed && generated_count >= warmup_count) {
                warmup_completed = true;
                std::cout << "[Dealer] Warmup complete (" << warmup_count 
                          << " items primed). Transitioning to idle background generation (interval=" 
                          << interval_ms << "ms)." << std::endl;
            }

            // Idle throttle: sleep if we have finished the initial warmup burst
            if (warmup_completed && interval_ms > 0) {
                // Sleep in small increments to respond immediately to SIGINT/Ctrl+C
                int64_t elapsed_ms = 0;
                while (elapsed_ms < interval_ms && !g_stop_requested.load()) {
                    int64_t step_ms = std::min<int64_t>(20, interval_ms - elapsed_ms);
                    std::this_thread::sleep_for(std::chrono::milliseconds(step_ms));
                    elapsed_ms += step_ms;
                }
                if (g_stop_requested.load()) break;
            }

            // 1. Sample uniformly random dummy index r in [0, db_blocks - 1]
            uint64_t r = dist_(rng_);

            // 2. Generate uniform XOR shares: r0 in [0, db_blocks - 1], r1 = r ^ r0
            uint64_t r0 = dist_(rng_);
            uint64_t r1 = r ^ r0;

            // 3. Generate DPF keys (k0, k1) targeting r
            DPFKey k0, k1;
            DPF::generate(r, block_depth_, k0, k1);

            // 4. Transmit (dpf_id, r0, k0) to Server 0
            write_uint64(socket0_, dpf_id);
            write_uint64(socket0_, r0);
            write_key(socket0_, k0);

            // 5. Transmit (dpf_id, r1, k1) to Server 1
            write_uint64(socket1_, dpf_id);
            write_uint64(socket1_, r1);
            write_key(socket1_, k1);

            // 6. Await ACKs from both servers (provides natural backpressure when server queue is full)
            uint8_t ack0 = 0, ack1 = 0;
            boost::asio::read(socket0_, boost::asio::buffer(&ack0, 1));
            boost::asio::read(socket1_, boost::asio::buffer(&ack1, 1));

            if (ack0 != 1 || ack1 != 1) {
                std::cerr << "[Dealer] Warning: Received invalid ACK from servers!" << std::endl;
                break;
            }

            if (dpf_id % 50 == 0 || dpf_id == 1) {
                std::cout << "[Dealer] Streamed DPF item ID=" << dpf_id 
                          << " (r_shares generated and DPF keys delivered)." << std::endl;
            }

            ++dpf_id;
            ++generated_count;
        }

        std::cout << "[Dealer] Precomputation loop finished. Total items streamed: " 
                  << (dpf_id - 1) << std::endl;
    }

private:
    boost::asio::io_context& io_context_;
    tcp::socket socket0_;
    tcp::socket socket1_;
    size_t db_blocks_;
    size_t block_depth_;
    std::mt19937_64 rng_;
    std::uniform_int_distribution<uint64_t> dist_;
};

int main(int argc, char* argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: dealer <host0> <port0> <host1> <port1> <db_size_power_of_2_chars> [options]\n"
                  << "Options:\n"
                  << "  --interval <ms>   Interval between keys during idle phase (default: 100 ms)\n"
                  << "  --warmup <N>      Initial burst keys generated without delay (default: 100)\n"
                  << "  --count <N>       Optional total keys to generate (default: 0 = continuous daemon)\n";
        return 1;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        std::string host0 = argv[1];
        std::string port0 = argv[2];
        std::string host1 = argv[3];
        std::string port1 = argv[4];

        size_t total_chars = 1ULL << std::atoi(argv[5]);
        size_t db_blocks = std::max(size_t(1), total_chars / 32);
        size_t block_depth = __builtin_ctzll(db_blocks);

        int64_t target_count = 0;       // 0 = continuous background daemon
        int64_t warmup_count = 100;     // Initial burst
        int64_t interval_ms = 100;      // 100 ms idle interval (10 keys/sec)

        // Parse optional arguments and flags
        for (int i = 6; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--interval" || arg == "-i") && i + 1 < argc) {
                interval_ms = std::atoll(argv[++i]);
            } else if ((arg == "--warmup" || arg == "-w") && i + 1 < argc) {
                warmup_count = std::atoll(argv[++i]);
            } else if ((arg == "--count" || arg == "-c") && i + 1 < argc) {
                target_count = std::atoll(argv[++i]);
            } else if (!arg.empty() && arg[0] != '-') {
                // Support legacy positional count
                target_count = std::atoll(arg.c_str());
            }
        }

        boost::asio::io_context io_context;
        Dealer dealer(io_context, host0, port0, host1, port1, db_blocks, block_depth);
        dealer.run(target_count, warmup_count, interval_ms);

    } catch (const std::exception& e) {
        std::cerr << "[Dealer] Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
