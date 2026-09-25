/*
 * Stateful DUORAM helper P2 and preprocessing dealer.
 * P2 distributes XOR Du–Atallah AND-triple shares to the computational parties,
 * retains its two blind shares, and stores only the DPF evaluations assigned to
 * it (P0 component 2 and P1 component 3). Online P2 receives masked XOR
 * permutation offsets, never the target index shares.
 */
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <memory>
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

    // Fills one 128-bit word directly from the platform random source.
    Block128 secure_random_block() {
        std::random_device source;
        const uint64_t lo = (uint64_t(source()) << 32) | source();
        const uint64_t hi = (uint64_t(source()) << 32) | source();
        return Block128(hi, lo);
    }

    void random_blocks(std::vector<Block128>& blocks) {
        for (auto& blk : blocks) {
            blk = secure_random_block();
        }
    }
}

/**
 * @brief Standalone offline Dealer class that produces correlated randomness for Server 0 and Server 1.
 *
 * The Dealer is the only party that has a global view of the secret-sharing setup. It generates
 * all blinding material offline and distributes shares to each server. The online servers never
 * need to communicate the full database to each other.
 */
class Dealer {
public:
    /**
     * @brief Constructs and connects the Dealer to both servers.
     *
     * Establishes two TCP connections: one ROLE_INIT channel (for the one-shot blinding array push)
     * and one ROLE_OFFLINE channel (for continuous DPF key streaming) to each server.
     *
     * @param io_context  Boost.Asio IO context.
     * @param host0       Hostname of Server 0.
     * @param port0       Port of Server 0.
     * @param host1       Hostname of Server 1.
     * @param port1       Port of Server 1.
     * @param db_blocks   Number of 128-bit database blocks.
     * @param block_depth log2(db_blocks) — DPF tree depth.
     */
    Dealer(boost::asio::io_context& io_context,
           const std::string& host0, const std::string& port0,
           const std::string& host1, const std::string& port1,
           size_t db_blocks, size_t block_depth, short helper_port)
        : io_context_(io_context),
          helper_acceptor_(io_context, tcp::endpoint(tcp::v4(), helper_port)),
          init_socket0_(io_context),
          init_socket1_(io_context),
          offline_socket0_(io_context),
          offline_socket1_(io_context),
          db_blocks_(db_blocks),
          block_depth_(block_depth)
    {
        tcp::resolver resolver(io_context_);
        auto ep0 = resolver.resolve(host0, port0);
        auto ep1 = resolver.resolve(host1, port1);

        // ---- ROLE_INIT connections (one-shot blinding array delivery) ----
        std::cout << "[Dealer] Connecting INIT channel to Server 0 (" << host0 << ":" << port0 << ")..." << std::endl;
        boost::asio::connect(init_socket0_, ep0);
        std::cout << "[Dealer] Connecting INIT channel to Server 1 (" << host1 << ":" << port1 << ")..." << std::endl;
        boost::asio::connect(init_socket1_, ep1);

        uint8_t role_init = ROLE_INIT;
        boost::asio::write(init_socket0_, boost::asio::buffer(&role_init, 1));
        boost::asio::write(init_socket1_, boost::asio::buffer(&role_init, 1));

        // ---- ROLE_OFFLINE connections (continuous DPF key stream) ----
        std::cout << "[Dealer] Connecting OFFLINE channel to Server 0..." << std::endl;
        boost::asio::connect(offline_socket0_, ep0);
        std::cout << "[Dealer] Connecting OFFLINE channel to Server 1..." << std::endl;
        boost::asio::connect(offline_socket1_, ep1);

        uint8_t role_offline = ROLE_OFFLINE;
        boost::asio::write(offline_socket0_, boost::asio::buffer(&role_offline, 1));
        boost::asio::write(offline_socket1_, boost::asio::buffer(&role_offline, 1));

        std::cout << "[Dealer] All channels established." << std::endl;
    }

    ~Dealer() {
        boost::system::error_code ignored;
        helper_acceptor_.close(ignored);
        if (helper_socket0_) helper_socket0_->shutdown(tcp::socket::shutdown_both, ignored);
        if (helper_socket1_) helper_socket1_->shutdown(tcp::socket::shutdown_both, ignored);
        if (helper_socket0_) helper_socket0_->close(ignored);
        if (helper_socket1_) helper_socket1_->close(ignored);
        if (helper_thread_.joinable()) helper_thread_.join();
    }

    /**
     * @brief Executes the startup O(N) blinding array generation and delivery.
     *
     * Generates independent XOR shares B0 and B1 of the helper's blind array.
     * Streams B0 to Server 0 and B1 to Server 1, and retains both shares for
     * the online read and update protocol.
     *
     * Must be called before run().
     */
    void initialize_blinds() {
        std::cout << "[Dealer] Generating blinding arrays B0, B1 (" << db_blocks_ << " blocks each)..." << std::endl;

        // Generate B0 with uniform randomness
        B0_.resize(db_blocks_);
        B1_.resize(db_blocks_);
        random_blocks(B0_);
        // B1[i] = B0[i] ^ B[i] where B[i] is also random; equivalently, B1 is independently random.
        // The true blind is B[i] = B0[i] ^ B1[i] — never reconstructed in the clear.
        random_blocks(B1_);

        // Push B0 to Server 0
        uint64_t count = static_cast<uint64_t>(db_blocks_);
        write_uint64(init_socket0_, count);
        boost::asio::write(init_socket0_,
            boost::asio::buffer(B0_.data(), db_blocks_ * sizeof(Block128)));

        // Push B1 to Server 1
        write_uint64(init_socket1_, count);
        boost::asio::write(init_socket1_,
            boost::asio::buffer(B1_.data(), db_blocks_ * sizeof(Block128)));

        // Await ACKs confirming F_b arrays have been exchanged between servers
        uint8_t ack0 = 0, ack1 = 0;
        boost::asio::read(init_socket0_, boost::asio::buffer(&ack0, 1));
        boost::asio::read(init_socket1_, boost::asio::buffer(&ack1, 1));

        if (ack0 != 1 || ack1 != 1) {
            throw std::runtime_error("[Dealer] Startup INIT handshake failed — servers did not ACK.");
        }

        std::cout << "[Dealer] Blinding arrays delivered. Servers have exchanged F0/F1." << std::endl;
    }

    /**
     * @brief Runs the two-phase offline DPF generation daemon.
     *
     * Streams Du-Atallah AND triples to the two servers. The servers choose
     * XOR-shared target indices and generate the leafless DPF components;
     * P2 receives only those components, which it needs for online blind
     * evaluation. P2 never chooses or learns the target index.
     *
     * @param target_count  Total items to generate (0 = continuous daemon, never stops).
     * @param warmup_count  Items to burst-generate at startup with no inter-item delay.
     * @param interval_ms   Inter-item sleep during steady-state idle phase (ms).
     */
    void run(int64_t target_count = 0, int64_t warmup_count = 100, int64_t interval_ms = 100) {
        helper_thread_ = std::thread([this]() { serve_online_helper(); });
        uint64_t dpf_id = 1;
        int64_t generated_count = 0;
        bool warmup_completed = false;

        if (target_count > 0) {
            std::cout << "[Dealer] Finite batch mode: target=" << target_count
                      << " items, warmup=" << warmup_count
                      << ", idle_interval=" << interval_ms << "ms" << std::endl;
        } else {
            std::cout << "[Dealer] Persistent daemon mode: warmup=" << warmup_count
                      << " items, idle_interval=" << interval_ms << "ms" << std::endl;
        }

        while (!g_stop_requested.load()) {
            if (target_count > 0 && generated_count >= target_count) {
                std::cout << "[Dealer] Preprocessing target of " << target_count
                          << " items reached." << std::endl;
                break;
            }

            // Phase transition: warmup burst -> paced idle
            if (!warmup_completed && generated_count >= warmup_count) {
                warmup_completed = true;
                std::cout << "[Dealer] Warmup complete (" << warmup_count
                          << " items). Switching to idle cadence (" << interval_ms << "ms)." << std::endl;
            }

            // Idle throttle in small increments for clean SIGINT response
            if (warmup_completed && interval_ms > 0) {
                int64_t elapsed_ms = 0;
                while (elapsed_ms < interval_ms && !g_stop_requested.load()) {
                    int64_t step = std::min<int64_t>(20, interval_ms - elapsed_ms);
                    std::this_thread::sleep_for(std::chrono::milliseconds(step));
                    elapsed_ms += step;
                }
                if (g_stop_requested.load()) break;
            }

            // Generate the AND preprocessing needed by the two servers to
            // jointly create index-private DPF material.
            const size_t triple_count = 6 * block_depth_;
            write_uint64(offline_socket0_, dpf_id);
            write_uint64(offline_socket1_, dpf_id);
            for (size_t i = 0; i < triple_count; ++i) {
                const auto triple = make_and_triple();
                write_and_triple(offline_socket0_, triple.first);
                write_and_triple(offline_socket1_, triple.second);
            }

            // P2 stores only its assigned DPF evaluations for later masked
            // blind evaluation; neither a target nor target share is sent here.
            DPFKey p0_component2, p1_component3;
            read_key(offline_socket0_, p0_component2);
            read_key(offline_socket1_, p1_component3);
            DuoramHelperPoolItem helper_item;
            helper_item.dpf_id = dpf_id;
            helper_item.material.party0_blind_component = duoram::make_dpf_share(
                DPF::evaluate_full_values(p0_component2, block_depth_));
            helper_item.material.party1_blind_component = duoram::make_dpf_share(
                DPF::evaluate_full_values(p1_component3, block_depth_));
            if (!helper_pool_.push(std::move(helper_item))) break;

            // Wait for both servers to finish producing the online material.
            uint8_t ack0 = 0, ack1 = 0;
            boost::asio::read(offline_socket0_, boost::asio::buffer(&ack0, 1));
            boost::asio::read(offline_socket1_, boost::asio::buffer(&ack1, 1));

            if (ack0 != 1 || ack1 != 1) {
                std::cerr << "[Dealer] Warning: Invalid ACK received. Stopping." << std::endl;
                break;
            }

            if (dpf_id % 50 == 0 || dpf_id == 1) {
                std::cout << "[Dealer] Generated index-private DPF material ID="
                          << dpf_id << std::endl;
            }

            ++dpf_id;
            ++generated_count;
        }

        std::cout << "[Dealer] Preprocessing stopped. Total items streamed: "
                  << (dpf_id - 1) << std::endl;

        // P2 remains an online protocol participant after a finite preprocessing
        // batch is generated. Returning here would destroy the helper sockets
        // before the client can use the queued material. SIGINT/SIGTERM ends
        // both the helper service and this wait.
        if (target_count > 0 && !g_stop_requested.load()) {
            std::cout << "[Dealer] Continuing as online helper P2; press Ctrl-C to stop."
                      << std::endl;
            while (!g_stop_requested.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

private:
    // P2 receives only the masked address offsets (uniform because r is fresh)
    // and its assigned DPF evaluations. It never receives either target share.
    void serve_online_helper() {
        try {
            for (int accepted = 0; accepted < 2; ++accepted) {
                auto channel = std::make_unique<tcp::socket>(io_context_);
                helper_acceptor_.accept(*channel);
                uint8_t role = 0;
                boost::asio::read(*channel, boost::asio::buffer(&role, 1));
                if (role == ROLE_HELPER0 && !helper_socket0_) {
                    helper_socket0_ = std::move(channel);
                } else if (role == ROLE_HELPER1 && !helper_socket1_) {
                    helper_socket1_ = std::move(channel);
                } else {
                    throw std::runtime_error("online helper received duplicate or invalid party role");
                }
            }
            std::cout << "[Dealer] Online helper channels connected." << std::endl;

            while (!g_stop_requested.load()) {
                uint8_t cmd0 = 0, cmd1 = 0;
                boost::asio::read(*helper_socket0_, boost::asio::buffer(&cmd0, 1));
                boost::asio::read(*helper_socket1_, boost::asio::buffer(&cmd1, 1));
                if (cmd0 != cmd1 ||
                    (cmd0 != CMD_HELPER_READ && cmd0 != CMD_HELPER_UPDATE)) {
                    throw std::runtime_error("unsupported or mismatched helper request");
                }

                uint64_t id0 = 0, id1 = 0, offset0 = 0, offset1 = 0;
                read_uint64(*helper_socket0_, id0);
                read_uint64(*helper_socket1_, id1);
                read_uint64(*helper_socket0_, offset0);
                read_uint64(*helper_socket1_, offset1);
                if (id0 != id1) throw std::runtime_error("helper DPF IDs are out of sync");

                Block128 final_blind0, final_blind1;
                if (cmd0 == CMD_HELPER_UPDATE) {
                    Block128 final_blind0_peer, final_blind1_peer;
                    read_block(*helper_socket0_, final_blind0);
                    read_block(*helper_socket0_, final_blind1);
                    read_block(*helper_socket1_, final_blind0_peer);
                    read_block(*helper_socket1_, final_blind1_peer);
                    if (final_blind0 != final_blind0_peer ||
                        final_blind1 != final_blind1_peer) {
                        throw std::runtime_error("parties disagree on update correction words");
                    }
                }

                DuoramHelperPoolItem item;
                if (!helper_pool_.pop(item) || item.dpf_id != id0) {
                    throw std::runtime_error("helper DPF preprocessing pool is out of sync");
                }

                const uint64_t public_offset = (offset0 ^ offset1) % db_blocks_;
                if (cmd0 == CMD_HELPER_READ) {
                    const auto t0_blind0 = duoram::xor_permute<uint8_t>(
                        item.material.party0_blind_component.flags, public_offset);
                    const auto t1_blind1 = duoram::xor_permute<uint8_t>(
                        item.material.party1_blind_component.flags, public_offset);
                    const Block128 rho = secure_random_block();
                    const auto gamma = duoram::helper_read_cancellation(
                        B0_, t1_blind1, B1_, t0_blind0, rho);
                    write_block(*helper_socket0_, gamma.gamma0);
                    write_block(*helper_socket1_, gamma.gamma1);
                } else {
                    const auto& dpf0 = item.material.party0_blind_component;
                    const auto& dpf1 = item.material.party1_blind_component;
                    const auto flags0 = duoram::xor_permute<uint8_t>(
                        dpf0.flags, public_offset);
                    const auto flags1 = duoram::xor_permute<uint8_t>(
                        dpf1.flags, public_offset);
                    const auto values0 = duoram::xor_permute<Block128>(
                        dpf0.values, public_offset);
                    const auto values1 = duoram::xor_permute<Block128>(
                        dpf1.values, public_offset);
                    const auto delta0 = duoram::corrected_update_vector(
                        values0, flags0, final_blind0);
                    const auto delta1 = duoram::corrected_update_vector(
                        values1, flags1, final_blind1);
                    for (size_t i = 0; i < db_blocks_; ++i) {
                        B0_[i] ^= delta0[i];
                        B1_[i] ^= delta1[i];
                    }
                    const uint8_t ack = 1;
                    boost::asio::write(*helper_socket0_, boost::asio::buffer(&ack, 1));
                    boost::asio::write(*helper_socket1_, boost::asio::buffer(&ack, 1));
                }
            }
        } catch (const std::exception& e) {
            if (!g_stop_requested.load()) {
                std::cerr << "[Dealer] Online helper stopped: " << e.what() << std::endl;
            }
        }
    }

    std::pair<duoram::BeaverAndTripleShare,
              duoram::BeaverAndTripleShare> make_and_triple() {
        duoram::BeaverAndTripleShare first;
        duoram::BeaverAndTripleShare second;
        first.x = secure_random_block();
        second.x = secure_random_block();
        first.y = secure_random_block();
        second.y = secure_random_block();
        const Block128 common_mask = secure_random_block();
        // Appendix A Du–Atallah AND triples (not ordinary Beaver triples):
        // Z0 = (X0 & Y1) ^ T and Z1 = (X1 & Y0) ^ T.
        first.z = (first.x & second.y) ^ common_mask;
        second.z = (second.x & first.y) ^ common_mask;
        return {first, second};
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor helper_acceptor_;
    std::unique_ptr<tcp::socket> helper_socket0_;
    std::unique_ptr<tcp::socket> helper_socket1_;
    std::thread helper_thread_;
    tcp::socket init_socket0_;    // ROLE_INIT channel to Server 0
    tcp::socket init_socket1_;    // ROLE_INIT channel to Server 1
    tcp::socket offline_socket0_; // ROLE_OFFLINE channel to Server 0
    tcp::socket offline_socket1_; // ROLE_OFFLINE channel to Server 1
    size_t db_blocks_;
    size_t block_depth_;
    // P2's two independent blind shares, also delivered separately at INIT.
    std::vector<Block128> B0_; // Server 0's blinding array share
    std::vector<Block128> B1_; // Server 1's blinding array share
    ThreadSafeQueue<DuoramHelperPoolItem> helper_pool_{200};
};

int main(int argc, char* argv[]) {
        if (argc < 6) {
        std::cerr << "Usage: dealer <host0> <port0> <host1> <port1> <db_size_power_of_2_chars> [options]\n"
                  << "Options:\n"
                  << "  --interval <ms>   Interval between keys in idle phase (default: 100 ms)\n"
                  << "  --warmup <N>      Initial burst key count with no delay (default: 100)\n"
                  << "  --count <N>       Preprocessing items to generate; then remain online as P2\n"
                  << "  --helper-port <P> Online P2 helper listener (default: 8002)\n";
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
        size_t db_blocks   = std::max(size_t(1), total_chars / 32);
        size_t block_depth = __builtin_ctzll(db_blocks);

        int64_t target_count = 0;
        int64_t warmup_count = 100;
        int64_t interval_ms  = 100;
        short helper_port = 8002;

        for (int i = 6; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--interval" || arg == "-i") && i + 1 < argc) {
                interval_ms = std::atoll(argv[++i]);
            } else if ((arg == "--warmup" || arg == "-w") && i + 1 < argc) {
                warmup_count = std::atoll(argv[++i]);
            } else if ((arg == "--count" || arg == "-c") && i + 1 < argc) {
                target_count = std::atoll(argv[++i]);
            } else if (arg == "--helper-port" && i + 1 < argc) {
                helper_port = static_cast<short>(std::atoi(argv[++i]));
            } else if (!arg.empty() && arg[0] != '-') {
                target_count = std::atoll(arg.c_str());
            }
        }

        boost::asio::io_context io_context;
        Dealer dealer(io_context, host0, port0, host1, port1, db_blocks,
                      block_depth, helper_port);
        dealer.initialize_blinds();
        dealer.run(target_count, warmup_count, interval_ms);

    } catch (const std::exception& e) {
        std::cerr << "[Dealer] Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
