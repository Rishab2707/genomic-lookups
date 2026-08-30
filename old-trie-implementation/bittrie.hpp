// bittrie.hpp
#ifndef __BITTRIE_HPP__
#define __BITTRIE_HPP__

#include "types.hpp"
#include "mpcio.hpp"
#include "coroutine.hpp"
#include "options.hpp"
#include "mpcops.hpp"
#include "duoram.hpp"
#include "mpcops.hpp" // For mpc_set_bit

class BitTrieClass {
public:
    // One bit per ORAM slot (no packing)
    Duoram<RegXS> bit_oram;
    // End-of-string markers: one slot per trie index
    Duoram<RegXS> second_oram;

    size_t num_items = 0;

    // NEW: constructor used by your call site: BitTrieClass tree(tio.player(), size);
    BitTrieClass(int player, size_t nbits)
        : bit_oram(player, nbits), second_oram(player, nbits) {}

    // Init APIs
    void init(MPCTIO &tio, yield_t &yield);
    void init(MPCTIO &tio, yield_t &yield, size_t n);

    // Bit ops (now 1 slot == 1 bit)
    void set_bit(MPCTIO &tio, yield_t &yield, RegXS bit_position, unsigned player);
    RegXS get_bit(MPCTIO &tio, yield_t &yield, RegXS bit_position, unsigned player);

    // Trie ops
    void insert(MPCTIO &tio, yield_t &yield, RegXS index, RegXS &insert_value, unsigned player);
    void search(MPCTIO &tio, yield_t &yield, RegXS index, RegBS &Z, unsigned player);

    // Debug
    void print_bittrie(MPCTIO &tio, yield_t &yield, size_t size);
    void print_bittrie_stringcheck(MPCTIO &tio, yield_t &yield, size_t size);
};

// Driver
void BitTrie(unsigned player, MPCIO &mpcio, const PRACOptions &opts, char **args);

#endif
