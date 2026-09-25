/*
 * dpf.cpp
 * 
 * Implements the generation and evaluation routines for the Distributed Point Function.
 * Uses a true cryptographic PRG (AES-NI) to stretch seeds level-by-level, ensuring 
 * that the final evaluated trees cancel out (XOR to 0) everywhere except at the target index.
 */
#include "dpf.hpp"
#include <random>
#include <iostream>
#include <stdexcept>
#include <limits>

namespace {
    Block128 random_block() {
        std::random_device rd;
        auto random_word = [&rd]() {
            return (uint64_t(rd()) << 32) | uint64_t(rd());
        };
        return Block128(random_word(), random_word());
    }

    Block128 bit_mask(bool bit) {
        return bit ? Block128(UINT64_MAX, UINT64_MAX) : Block128{};
    }
}

DPFKey DPF::generate_shared(
    int party_id, uint64_t target_share, size_t depth,
    const std::function<Block128(const Block128&, const Block128&)>& secure_and,
    const std::function<Block128(const Block128&)>& exchange_block,
    const std::function<bool(bool)>& exchange_xor_bit) {
    if (party_id != 0 && party_id != 1) {
        throw std::invalid_argument("DPF party_id must be 0 or 1");
    }
    if (depth >= 64 || (depth == 0 ? target_share != 0
                                   : target_share >= (uint64_t{1} << depth))) {
        throw std::invalid_argument("DPF target share is outside the supported domain");
    }
    if (depth >= std::numeric_limits<size_t>::digits) {
        throw std::invalid_argument("DPF depth exceeds the local address space");
    }
    if (!secure_and || !exchange_block || !exchange_xor_bit) {
        throw std::invalid_argument("DPF joint-generation callbacks must be provided");
    }

    DPFKey key;
    key.party_id = party_id;
    key.seed = random_block();
    key.seed.set_lsb(party_id != 0);
    key.cw.resize(depth);
    key.t_cw_L.resize(depth);
    key.t_cw_R.resize(depth);

    PRG prg;
    std::vector<Block128> seeds{key.seed};
    std::vector<uint8_t> controls{static_cast<uint8_t>(party_id != 0)};

    for (size_t level = 0; level < depth; ++level) {
        const bool target_bit_share =
            ((target_share >> (depth - level - 1)) & 1U) != 0;

        std::vector<Block128> left_children(seeds.size());
        std::vector<Block128> right_children(seeds.size());
        std::vector<uint8_t> left_flags(seeds.size());
        std::vector<uint8_t> right_flags(seeds.size());
        Block128 left_sum, right_sum;
        bool left_flag_sum = false;
        bool right_flag_sum = false;
        for (size_t i = 0; i < seeds.size(); ++i) {
            Block128 left, right;
            prg.expand(seeds[i], left, right);
            left_flags[i] = static_cast<uint8_t>(left.lsb());
            right_flags[i] = static_cast<uint8_t>(right.lsb());
            left_flag_sum ^= left_flags[i] != 0;
            right_flag_sum ^= right_flags[i] != 0;
            left.set_lsb(false);
            right.set_lsb(false);
            left_children[i] = left;
            right_children[i] = right;
            left_sum ^= left;
            right_sum ^= right;
        }

        // The target bit is shared between P0/P1. For the second product,
        // P0 contributes the public one in the XOR sharing of 1 ^ target.
        const Block128 target_mask = bit_mask(target_bit_share);
        const Block128 not_target_mask = bit_mask(target_bit_share ^ (party_id == 0));
        const Block128 left_product = secure_and(target_mask, left_sum);
        const Block128 right_product = secure_and(not_target_mask, right_sum);
        const Block128 cw_share = left_product ^ right_product;
        const Block128 cw = exchange_block(cw_share);

        // Correction flags follow the BGI DPF construction. The left bit is
        // complemented once globally; the right bit is not.
        const bool local_left_cw = left_flag_sum ^ target_bit_share;
        const bool local_right_cw = right_flag_sum ^ target_bit_share;
        const bool cw_left = exchange_xor_bit(local_left_cw) ^ true;
        const bool cw_right = exchange_xor_bit(local_right_cw);
        key.cw[level] = cw;
        key.t_cw_L[level] = cw_left;
        key.t_cw_R[level] = cw_right;

        std::vector<Block128> next_seeds(seeds.size() * 2);
        std::vector<uint8_t> next_controls(seeds.size() * 2);
        for (size_t i = 0; i < seeds.size(); ++i) {
            Block128 left = left_children[i];
            Block128 right = right_children[i];
            bool left_flag = left_flags[i] != 0;
            bool right_flag = right_flags[i] != 0;
            if (controls[i] != 0) {
                left ^= cw;
                right ^= cw;
                left_flag ^= cw_left;
                right_flag ^= cw_right;
            }
            next_seeds[2 * i] = left;
            next_seeds[2 * i + 1] = right;
            next_controls[2 * i] = static_cast<uint8_t>(left_flag);
            next_controls[2 * i + 1] = static_cast<uint8_t>(right_flag);
        }
        seeds = std::move(next_seeds);
        controls = std::move(next_controls);
    }
    return key;
}

void DPF::generate(size_t target_index, size_t depth, DPFKey& key0, DPFKey& key1) {
    PRG prg;
    
    // Secure random generation for the initial seeds
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    Block128 s0(gen(), gen()); 
    Block128 s1(gen(), gen());
    
    key0.party_id = 0;
    key1.party_id = 1;
    key0.seed = s0;
    key1.seed = s1;
    
    // Initial control bits: Party 0 starts with 0, Party 1 starts with 1
    bool t0 = false;
    bool t1 = true;
    
    // Pre-allocate correction word vectors to exactly match the depth of the tree
    key0.cw.resize(depth);
    key1.cw.resize(depth);
    key0.t_cw_L.resize(depth);
    key1.t_cw_L.resize(depth);
    key0.t_cw_R.resize(depth);
    key1.t_cw_R.resize(depth);
    
    // Traverse the tree downwards, level by level
    for (size_t i = 0; i < depth; ++i) {
        Block128 s0_L, s0_R, s1_L, s1_R;
        
        // Expand current seeds into left/right children using the PRG
        prg.expand(s0, s0_L, s0_R);
        prg.expand(s1, s1_L, s1_R);
        
        // Extract the control bit (t) from the LSB of the PRG outputs
        bool t0_L = s0_L.lsb(); bool t0_R = s0_R.lsb();
        bool t1_L = s1_L.lsb(); bool t1_R = s1_R.lsb();
        
        // Clear the LSB so it doesn't affect future PRG expansions
        s0_L.set_lsb(false); s0_R.set_lsb(false);
        s1_L.set_lsb(false); s1_R.set_lsb(false);
        
        // Determine whether the target path goes left (0) or right (1) at this depth
        bool keep_right = (target_index >> (depth - 1 - i)) & 1;
        
        // 'keep' variables follow the target path; 'lose' variables follow the off-path
        Block128 s_lose_0 = keep_right ? s0_L : s0_R;
        Block128 s_lose_1 = keep_right ? s1_L : s1_R;
        
        // The Correction Word forces the off-path seeds to become identical (canceling out to 0)
        Block128 cw = s_lose_0 ^ s_lose_1;
        
        // Calculate flag correction bits to ensure control bits diverge precisely on the target path
        bool t_lose_0 = keep_right ? t0_L : t0_R;
        bool t_lose_1 = keep_right ? t1_L : t1_R;
        bool t_cw_lose = t_lose_0 ^ t_lose_1;
        
        bool t_keep_0 = keep_right ? t0_R : t0_L;
        bool t_keep_1 = keep_right ? t1_R : t1_L;
        bool t_cw_keep = t_keep_0 ^ t_keep_1 ^ 1; 
        
        bool t_cw_L = keep_right ? t_cw_lose : t_cw_keep;
        bool t_cw_R = keep_right ? t_cw_keep : t_cw_lose;
        
        // Both parties get identical copies of the Correction Words and Flags
        key0.cw[i] = cw;
        key1.cw[i] = cw;
        key0.t_cw_L[i] = t_cw_L;
        key1.t_cw_L[i] = t_cw_L;
        key0.t_cw_R[i] = t_cw_R;
        key1.t_cw_R[i] = t_cw_R;
        
        // If a party's control bit is 1, they conditionally apply the correction words
        if (t0) {
            s0_L ^= cw; s0_R ^= cw;
            t0_L ^= t_cw_L; t0_R ^= t_cw_R;
        }
        if (t1) {
            s1_L ^= cw; s1_R ^= cw;
            t1_L ^= t_cw_L; t1_R ^= t_cw_R;
        }
        
        // Proceed down the target path for the next level
        s0 = keep_right ? s0_R : s0_L;
        s1 = keep_right ? s1_R : s1_L;
        t0 = keep_right ? t0_R : t0_L;
        t1 = keep_right ? t1_R : t1_L;
    }
    
    // In Leafless DPF, no terminal correction word (final_cw) is created.
    // The control bits t_0 and t_1 at the final depth already form XOR shares of e_alpha.
}

std::vector<bool> DPF::evaluate_full(const DPFKey& key, size_t depth) {
    PRG prg;
    
    // Initialize the root level with the starting seed and control bit
    std::vector<Block128> s_prev = {key.seed};
    std::vector<bool> t_prev = {key.party_id == 1};
    
    // Iteratively expand the tree level by level
    for (size_t i = 0; i < depth; ++i) {
        std::vector<Block128> s_next(1ULL << (i + 1));
        std::vector<bool> t_next(1ULL << (i + 1));
        
        for (size_t j = 0; j < (1ULL << i); ++j) {
            Block128 sL, sR;
            prg.expand(s_prev[j], sL, sR);
            
            bool tL = sL.lsb(); bool tR = sR.lsb();
            sL.set_lsb(false); sR.set_lsb(false);
            
            // Conditionally apply correction words if the current path's control bit is 1
            if (t_prev[j]) {
                sL ^= key.cw[i]; sR ^= key.cw[i];
                tL ^= key.t_cw_L[i]; tR ^= key.t_cw_R[i];
            }
            
            s_next[2 * j] = sL;
            s_next[2 * j + 1] = sR;
            t_next[2 * j] = tL;
            t_next[2 * j + 1] = tR;
        }
        
        // Move to the next depth level
        s_prev = std::move(s_next);
        t_prev = std::move(t_next);
    }
    
    // The terminal control bits (t_prev) are the XOR secret shares of the one-hot basis vector e_r
    return t_prev;
}

DpfEvaluation DPF::evaluate_full_values(const DPFKey& key, size_t depth) {
    PRG prg;
    std::vector<Block128> seeds{key.seed};
    std::vector<uint8_t> flags{static_cast<uint8_t>(key.party_id == 1)};

    for (size_t level = 0; level < depth; ++level) {
        const size_t child_count = size_t{1} << (level + 1);
        std::vector<Block128> next_seeds(child_count);
        std::vector<uint8_t> next_flags(child_count);

        for (size_t node = 0; node < seeds.size(); ++node) {
            Block128 left, right;
            prg.expand(seeds[node], left, right);
            bool left_flag = left.lsb();
            bool right_flag = right.lsb();
            left.set_lsb(false);
            right.set_lsb(false);

            if (flags[node] != 0) {
                left ^= key.cw[level];
                right ^= key.cw[level];
                left_flag ^= key.t_cw_L[level];
                right_flag ^= key.t_cw_R[level];
            }

            next_seeds[2 * node] = left;
            next_seeds[2 * node + 1] = right;
            next_flags[2 * node] = static_cast<uint8_t>(left_flag);
            next_flags[2 * node + 1] = static_cast<uint8_t>(right_flag);
        }
        seeds = std::move(next_seeds);
        flags = std::move(next_flags);
    }

    Block128 final_correction;
    for (const auto& value : seeds) {
        final_correction ^= value;
    }
    return {std::move(flags), std::move(seeds), final_correction};
}

bool DPF::evaluate_at(const DPFKey& key, size_t depth, size_t index) {
    PRG prg;
    Block128 s = key.seed;
    bool t = (key.party_id == 1);
    
    // Walk down the single path toward the specific index
    for (size_t i = 0; i < depth; ++i) {
        bool go_right = (index >> (depth - 1 - i)) & 1;
        
        // We only expand the child we actually need
        Block128 child = prg.expand_single(s, go_right);
        bool child_t = child.lsb();
        child.set_lsb(false);
        
        if (t) {
            child ^= key.cw[i];
            child_t ^= go_right ? key.t_cw_R[i] : key.t_cw_L[i];
        }
        
        s = child;
        t = child_t;
    }
    
    return t;
}
