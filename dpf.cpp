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
