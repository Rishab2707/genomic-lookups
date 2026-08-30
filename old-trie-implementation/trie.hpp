//#ifndef __HEAP_HPP__
#define __HEAP_HPP__

#include "types.hpp"
#include "mpcio.hpp"
#include "coroutine.hpp"
#include "options.hpp"
#include "mpcops.hpp"
#include "duoram.hpp"

class TrieClass {
public:
    //Duoram < RegAS > oram;
    Duoram < RegXS> oram;
    Duoram < RegXS> second_oram;
    size_t MAX_SIZE;
    size_t num_items;

    // Basic restore heap property at a secret shared index
    // Takes in as an input the XOR shares of the index at which
    // the heap property has to be restored
    // Returns the XOR shares of the index of the smaller child
    // RegXS restore_heap_property(MPCTIO &tio, yield_t & yield, RegXS index);

    // Optimized restore heap property at a secret shared index
    // Takes in as an input the XOR shares of the index at which
    // the heap property has to be restored
    // Returns the XOR shares of the index of the smaller child and
    // comparison between the left and right child
    //std::pair<RegXS, RegBS> restore_heap_property_optimized(MPCTIO &tio, yield_t & yield, RegXS index, size_t layer, typename Duoram<RegAS>::template OblivIndex<RegXS,3> oidx);

    // Restore heap property at an index in clear
    // Takes in as an input the index (in clear) at which
    // the heap property has to be restored
    // Returns the XOR shares of the index of the smaller child and
    // comparison between the left and right child
    //std::pair<RegXS, RegBS> restore_heap_property_at_explicit_index(MPCTIO &tio, yield_t & yield,  size_t index);

public:
    TrieClass(int player_num, size_t size) : oram(player_num, size), second_oram(player_num,size) {};

    // The extractmin protocol returns the minimum element (the root), removes it
    // and restores the heap property
    // and takes in a boolean parameter to decide if the basic or the optimized version needs to be run
    // return value is the share of the minimum value (the root)
    RegAS extract_min(MPCTIO &tio, yield_t & yield, int is_optimized = 1);

    // Intializes the heap array with 0x7fffffffffffffff
    void init(MPCTIO &tio, yield_t & yield);

    // This function simply inits a heap with values 100,200,...,100*n
    // We use this function only to set up our heap
    // to do timing experiments on insert and extractmins
    void init(MPCTIO &tio, yield_t & yield, size_t n);

    void print_trie_stringcheck(MPCTIO &tio, yield_t &yield, size_t size);

    //Duoram <RegXS> getSecondOram() { return second_oram; };

    // The Basic Insert Protocol
    // Takes in the additive share of the value to be inserted
    // And adds the the value into the heap while keeping the heap property intact
    void insert(MPCTIO &tio, yield_t &yield, RegXS val, RegXS &y, unsigned player);

    void search(MPCTIO &TIO, yield_t & yield, RegXS val,RegBS &Z,unsigned player);

    void basic(MPCIO &MPCIO, yield_t &yield, int alphasize, int triedepth, size_t n_inserts, size_t n_searches , int is_optimized, unsigned player);

    // The Optimized Insert Protocol
    // Takes in the additive share of the value to be inserted
    // And adds the the value into the heap while keeping the heap property intact
    void insert_optimized(MPCTIO &tio, yield_t & yield, RegAS val);

    // Note: This function is intended for testing purposes only.
    // The purpose of this function is to verify that the heap property is satisfied.
    void verify_heap_property(MPCTIO &tio, yield_t & yield);


    // Prints the current trie
    void print_trie(MPCTIO &tio, yield_t & yield, size_t size);
};

void Trie(unsigned player,MPCIO &mpcio, const PRACOptions &opts, char **args);

//#endif
