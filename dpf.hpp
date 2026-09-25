/*
 * dpf.hpp
 * 
 * Defines the Distributed Point Function (DPF) structures and logic based on the 
 * Boyle-Gilboa-Ishai (BGI) construction. It allows a client to generate two keys 
 * that can be evaluated independently by two non-colluding servers.
 */
#pragma once

#include "prg.hpp"
#include <functional>
#include <vector>
#include <cstdint>

// Represents a DPF key assigned to one of the computing parties.
struct DPFKey {
    int party_id;                  // 0 or 1, determines the initial control bit 't'
    Block128 seed;                 // The 128-bit initial seed for the PRG tree
    std::vector<Block128> cw;      // Correction Words for each level of the tree
    std::vector<bool> t_cw_L;      // Left correction flag bits for each level
    std::vector<bool> t_cw_R;      // Right correction flag bits for each level
};

struct DpfEvaluation {
    // XOR shares of the point-function flag and the uncorrected value leaves.
    std::vector<uint8_t> flags;
    // Every leaf is a full 128-bit PRG label. This is a leafless DPF: the key
    // carries no terminal correction word; preprocessing derives the deferred
    // correction from these evaluated labels when an UPDATE needs it.
    std::vector<Block128> values;
    // XOR reduction of this party's leaf labels (the local deferred-CW share).
    Block128 final_correction;
};

class DPF {
public:
    // Generates a pair of Leafless keys (Key0 and Key1) for a specific target index (alpha).
    // The keys are generated such that when evaluated, their control bits yield XOR shares 
    // of a one-hot basis vector e_alpha (1 at the target index, and 0 everywhere else).
    // @param target_index The secret index (alpha) the DPF points to.
    // @param depth The depth of the tree (log2 of the total database size).
    // @param key0 The generated key for Party 0.
    // @param key1 The generated key for Party 1.
    static void generate(size_t target_index, size_t depth, DPFKey& key0, DPFKey& key1);

    // Jointly constructs one key share at each computational party from XOR
    // shares of the target. secure_and returns this party's share of the
    // bitwise product; exchange_block reconstructs an agreed correction word.
    // Both callbacks are driven by P2-generated preprocessing material, so P2
    // never receives either target share or any opened target bit.
    static DPFKey generate_shared(
        int party_id, uint64_t target_share, size_t depth,
        const std::function<Block128(const Block128&, const Block128&)>& secure_and,
        const std::function<Block128(const Block128&)>& exchange_block,
        const std::function<bool(bool)>& exchange_xor_bit);

    // Completely evaluates the Leafless DPF tree for all 2^depth possible indices.
    // Expands the key into a vector of boolean XOR shares of the one-hot vector.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @return A vector of boolean flags representing the expanded XOR shares.
    static std::vector<bool> evaluate_full(const DPFKey& key, size_t depth);

    // Evaluates both the DPF flags and the value labels used by UPDATE.
    static DpfEvaluation evaluate_full_values(const DPFKey& key, size_t depth);
    
    // Evaluates the DPF key at a single specific index.
    // Useful for debugging or for sparse tree evaluation without expanding the whole tree.
    // @param key The DPF key to evaluate.
    // @param depth The depth of the tree.
    // @param index The index to evaluate at.
    // @return The evaluated boolean share at index.
    static bool evaluate_at(const DPFKey& key, size_t depth, size_t index);
};
