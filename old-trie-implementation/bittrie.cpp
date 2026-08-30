// bittrie.cpp
#include <functional>
#include <cmath> // will remove pow usage below; see integer helpers further down
#include "types.hpp"
#include "duoram.hpp"
#include "cell.hpp"
#include "rdpf.hpp"
#include "shapes.hpp"
#include "bittrie.hpp"
#include <string>
#include <cstdlib>

#include "mpcops.hpp" 

// Defining this constant for clarity
const uint64_t BITS_PER_WORD = 64;
// Runtime switch for optional debug/reconstruction output
static bool BITTRIE_DEBUG_ENABLED = false;

// Forward declaration so BitTrie(...) can call it
static void basic_bit(MPCIO &mpcio,
                      yield_t &yield,
                      int alphasize,
                      int triedepth,
                      size_t n_inserts,
                      size_t n_searches,
                      int is_optimized,
                      unsigned player,
                      MPCTIO &tio);




void BitTrie(unsigned p, MPCIO &mpcio, const PRACOptions &opts, char **args) {
    MPCTIO tio(mpcio, 0, opts.num_cpu_threads);

    int nargs = 0;
    while (args[nargs] != nullptr) ++nargs;

    unsigned player = p;
    int alphasize = 0;
    int triedepth = 0;
    size_t n_inserts = 0;
    size_t n_searches = 0;
    int is_optimized = 0;
    int run_sanity = 0;
    int debug_flag = 0; // default: no verbose reconstruction

    for (int i = 0; i < nargs; i += 2) {
        std::string option = args[i];
        if (option == "-m"   && i + 1 < nargs) alphasize   = std::atoi(args[i + 1]);
        else if (option == "-d"   && i + 1 < nargs) triedepth   = std::atoi(args[i + 1]);
        else if (option == "-i"   && i + 1 < nargs) n_inserts   = std::atoi(args[i + 1]);
        else if (option == "-e"   && i + 1 < nargs) n_searches  = std::atoi(args[i + 1]);
        else if (option == "-opt" && i + 1 < nargs) is_optimized= std::atoi(args[i + 1]);
        else if (option == "-s"   && i + 1 < nargs) run_sanity  = std::atoi(args[i + 1]);
        else if (option == "-debug" && i + 1 < nargs) debug_flag = std::atoi(args[i + 1]);
    }

    BITTRIE_DEBUG_ENABLED = (debug_flag != 0);

    run_coroutines(tio, [&tio, alphasize, triedepth, n_inserts, n_searches,
                         is_optimized, run_sanity, player, &mpcio](yield_t &yield) {
        basic_bit(mpcio, yield, alphasize, triedepth, n_inserts,
                  n_searches, is_optimized, player, tio);
    });
}


// ---- Init ----
void BitTrieClass::init(MPCTIO &tio, yield_t &yield) {
    auto BitArray = bit_oram.flat(tio, yield);
    BitArray.init([](size_t){ return RegXS{}; }); // all zeros
    num_items = 0;
}

void BitTrieClass::init(MPCTIO &tio, yield_t &yield, size_t n) {
    num_items = n;
    auto BitArray    = bit_oram.flat(tio, yield);
    auto StringArray = second_oram.flat(tio, yield);
    BitArray.init([](size_t){ return RegXS{}; });    // 0
    StringArray.init([](size_t){ return RegXS{}; }); // 0
}

// ---- Per-bit set/get (1 slot == 1 bit) ----#including secure mpc computations
void BitTrieClass::set_bit(MPCTIO &tio, yield_t &yield, RegXS bit_position, unsigned player) {
    auto BitArray = bit_oram.flat(tio, yield);

    // --- DEBUG: Reconstruct the secret bit_position we want to set ---
    if (BITTRIE_DEBUG_ENABLED) {
        if (player == 0) {
            value_t public_bit_pos = mpc_reconstruct(tio, yield, bit_position, 32);
            std::cout << "\n[DEBUG] SETTING bit_position: " << public_bit_pos << std::endl;
        } else {
            mpc_reconstruct(tio, yield, bit_position, 32); // P1 must participate
        }
    }

    // --- 1. SECURELY GET THE WORD INDEX ---
    RegXS word_idx;
    mpc_secret_shift_right(word_idx, bit_position, 6);

    // --- 2. OBLIVIOUSLY READ THE OLD WORD ---
    RegXS old_word = BitArray[word_idx];
    
    // --- DEBUG: Reconstruct values to see what's happening ---
    if (BITTRIE_DEBUG_ENABLED) {
        if (player == 0) {
            value_t public_word_idx = mpc_reconstruct(tio, yield, word_idx, 32);
            value_t public_old_word = mpc_reconstruct(tio, yield, old_word, 64);
            std::cout << "[DEBUG]   Reading from word_idx: " << public_word_idx << std::endl;
            std::cout << "[DEBUG]   Value of old_word: " << public_old_word << std::endl;
        } else {
            mpc_reconstruct(tio, yield, word_idx, 32); // P1 must participate
            mpc_reconstruct(tio, yield, old_word, 64); // P1 must participate
        }
    }

    // --- 3. HYBRID STEP: Reconstruct ONLY the bit index (0-63) ---
    RegXS bit_in_word_idx_xs;
    mpc_and_public(tio, yield, bit_in_word_idx_xs, bit_position, 63, player);
    uint8_t public_bit_idx = mpc_reconstruct(tio, yield, bit_in_word_idx_xs, 6);
    
    if (BITTRIE_DEBUG_ENABLED && player == 0) {
        std::cout << "[DEBUG]   Calculated public_bit_idx (0-63): " << (int)public_bit_idx << std::endl;
    }

    // Create a secret share for the value '1'
    RegBS one_bs;
    one_bs.bshare = (player == 0);

    // --- 4. USE HELPER TO MODIFY THE WORD ---
    RegXS new_word = old_word;
    mpc_set_bit(tio, yield, new_word, public_bit_idx, one_bs, player); // Calling the FIXED function // Calling the BROKEN function

    // --- DEBUG: Reconstruct the new word to check the result ---
    if (BITTRIE_DEBUG_ENABLED) {
        if (player == 0) {
            value_t public_new_word = mpc_reconstruct(tio, yield, new_word, 64);
            std::cout << "[DEBUG]   Value of new_word after set: " << public_new_word << std::endl;
        } else {
            mpc_reconstruct(tio, yield, new_word, 64); // P1 must participate
        }
    }

    // --- 5. CRITICAL STEP: WRITE THE MODIFIED WORD BACK ---
    BitArray[word_idx] = new_word;
}


RegXS BitTrieClass::get_bit(MPCTIO &tio, yield_t &yield, RegXS bit_position, unsigned player) {
    auto BitArray = bit_oram.flat(tio, yield);

    // --- 1. SECURELY GET THE WORD INDEX ---
    RegXS word_idx;
    mpc_secret_shift_right(word_idx, bit_position, 6); // Securely calculate word index

    // --- 2. OBLIVIOUSLY READ THE WORD ---
    RegXS word = BitArray[word_idx];
    
    // --- 3. HYBRID STEP: Reconstruct ONLY the bit index (0-63) ---
    RegXS bit_in_word_idx_xs;
    mpc_and_public(tio, yield, bit_in_word_idx_xs, bit_position, 63, player);
    // This reconstruction is much less risky as it only reveals 6 bits of info
    uint8_t public_bit_idx = mpc_reconstruct(tio, yield, bit_in_word_idx_xs, 6);

    // --- 4. USE HELPER WITH THE NOW-PUBLIC BIT INDEX ---
    RegBS result_bs;
    mpc_get_bit(result_bs, word, public_bit_idx);

    RegXS result_xs;
    result_xs.xshare = result_bs.bshare;
    return result_xs;
}


// ---- Trie insert/search ----
void BitTrieClass::insert(MPCTIO &tio, yield_t &yield, RegXS index, RegXS & /*insert_value*/, unsigned player) {
    num_items++;
    // Mark path bit
    set_bit(tio, yield, index, player);
}

void BitTrieClass::search(MPCTIO &tio, yield_t &yield, RegXS index, RegBS &Z, unsigned player) {
    // Z := Z AND (bit_at_index == 1)
    RegXS bitv = get_bit(tio, yield, index, player);    // 0/1 in XOR share
    RegBS bval = bitv.bitat(0);                 // safe: value is 0/1, bit 0 equals the value
    RegBS tmp;
    mpc_and(tio, yield, tmp, Z, bval);
    Z = tmp;
}

// ---- Debug print helpers (only P0 sees data) ----
void BitTrieClass::print_bittrie(MPCTIO &tio, yield_t &yield, size_t size) {
    if (!BITTRIE_DEBUG_ENABLED) return;
    auto BitArray = bit_oram.flat(tio, yield);
    auto R = BitArray.reconstruct();
    if (R.empty()) return; // P1/P2 get empty
    for (size_t i = 0; i < size; ++i) {
        uint64_t v = R[i].share();
        std::cout << i << "->" << v << "   ";
    }
}

void BitTrieClass::print_bittrie_stringcheck(MPCTIO &tio, yield_t &yield, size_t size) {
    if (!BITTRIE_DEBUG_ENABLED) return;
    auto StringArray = second_oram.flat(tio, yield);
    auto R = StringArray.reconstruct();
    if (R.empty()) return;
    for (size_t i = 0; i < size; ++i) {
        std::cout << i << "->" << (R[i].share()) << "   ";
    }
}

// ===== helpers: integer math (no std::pow on size_t) =====
static size_t ipow(size_t base, size_t exp) {
    size_t res = 1;
    while (exp) {
        if (exp & 1) res = res * base;
        exp >>= 1;
        if (exp) base = base * base;
    }
    return res;
}
static size_t geom_sum_levels(size_t n, size_t m) {
    // 1 + n + n^2 + ... + n^m
    if (m == 0) return 1;
    size_t sum = 1, term = 1;
    for (size_t k = 1; k <= m; ++k) {
        term *= n;
        sum  += term;
    }
    return sum;
}

// ===== your driver (keep your arrays & flags) =====
#define BITTRIE_VERBOSE
static int preIndex_bit[10];

static int letterToIndex_bit(char x, int pos, int alphasize, int is_optimized, int preIndex_bit[]) {
    int ch = (is_optimized == 1) ? (x - 'a') : (x - 'a' + 1);
    if (pos == 0) {
        preIndex_bit[pos] = ch;
        return ch;
    } else {
        preIndex_bit[pos] = preIndex_bit[pos-1] * alphasize + ch;
        return preIndex_bit[pos];
    }
}

static size_t sumOfPowers_bit(size_t n, size_t m) {
    // You were using doubles; switch to exact integer version
    // If your trie uses levels 0..m, the total nodes is 1 + n + ... + n^m
    return geom_sum_levels(n, m);
}

static size_t Power_bit(size_t x, size_t y) {
    // You used pow(x, y+1); keep intent but exact
    return ipow(x, y+1);
}

// In thesis/bittrie.cpp -- THE FULLY CORRECTED basic_bit function

void basic_bit(MPCIO &mpcio, yield_t &yield, int alphasize, int triedepth,
               size_t n_inserts, size_t n_searches, int is_optimized,
               unsigned player, MPCTIO &tio)
{
    size_t nbits = sumOfPowers_bit(alphasize, triedepth) + 1;
    size_t size = (nbits + 63) / 64;
    std::cout << "BitTrie size: " << nbits << " bits in " << size << " words\n";

    BitTrieClass tree(tio.player(), size);
    tree.init(tio, yield, size);

#ifdef BITTRIE_VERBOSE
    if (BITTRIE_DEBUG_ENABLED) {
        tree.print_bittrie(tio, yield, size);
    }
    std::cout << "\n===== BitTrie Init Stats =====\n";
#endif
    tio.sync_lamport();
    mpcio.dump_stats(std::cout);
    mpcio.reset_stats();
    tio.reset_lamport();

    std::string insertArray[] = {"dad","aab","aca","daa","dca"};
    std::string searchArray[] = {"ddd","aab","aca","daa","dca"};

    // ---------- INSERT ----------
    for (size_t i = 0; i < n_inserts; i++) {
        RegXS share;
        int preIndex_bit[10] = {0}; // Create a fresh array for each string

        for (size_t j = 0; j < insertArray[i].length(); j++) {
            // Pass the array to the function
            int inserted_index = letterToIndex_bit(insertArray[i][j], (int)j, alphasize, is_optimized, preIndex_bit);
            share.xshare = (player == 0) ? inserted_index : 0;
            RegXS dummy;
            tree.insert(tio, yield, share, dummy, player);
        }

        // --- CORRECTED End-of-String MARKER ---
        // (This part was already correct from the last fix)
        auto End_String = tree.second_oram.flat(tio, yield);
        RegXS word_idx_eos;
        mpc_secret_shift_right(word_idx_eos, share, 6);
        RegXS old_word_eos = End_String[word_idx_eos];
        RegXS bit_in_word_idx_xs;
        mpc_and_public(tio, yield, bit_in_word_idx_xs, share, 63, player);
        uint8_t public_bit_idx_eos = mpc_reconstruct(tio, yield, bit_in_word_idx_xs, 6);
        RegBS one_bs_eos; one_bs_eos.bshare = (player == 0);
        RegXS new_word_eos = old_word_eos;
        mpc_set_bit(tio, yield, new_word_eos, public_bit_idx_eos, one_bs_eos, player);
        End_String[word_idx_eos] = new_word_eos;


        if (BITTRIE_DEBUG_ENABLED) {
            std::cout << "\ninserted value is " << insertArray[i] << std::endl;
        }
#ifdef BITTRIE_VERBOSE
        if (BITTRIE_DEBUG_ENABLED) {
            tree.print_bittrie(tio, yield, size);
            std::cout << "\nString presence array \n";
            tree.print_bittrie_stringcheck(tio, yield, size);
            std::cout << "\n";
        }
#endif
    }

    std::cout << "\n===== BitTrie Insert Stats =====\n";
    tio.sync_lamport();
    mpcio.dump_stats(std::cout);
    mpcio.reset_stats();
    tio.reset_lamport();

    // ---------- SEARCH ----------
    for (size_t i = 0; i < n_searches; i++) {
        RegBS Z; Z.bshare = (player == 0);
        RegXS share;
        int preIndex_bit[10] = {0}; // Create a fresh array for each search

        for (size_t j = 0; j < searchArray[i].length(); j++) {
            // Pass the array to the function
            int inserted_index = letterToIndex_bit(searchArray[i][j], (int)j, alphasize, is_optimized, preIndex_bit);
            share.xshare = (player == 0) ? inserted_index : 0;
            tree.search(tio, yield, share, Z, player);
        }
        
        // --- CORRECTED End-of-String CHECK ---
        // (This part was also correct from the last fix)
        auto End_String = tree.second_oram.flat(tio, yield);
        RegXS word_idx_eos;
        mpc_secret_shift_right(word_idx_eos, share, 6);
        RegXS word_eos = End_String[word_idx_eos];
        RegXS bit_in_word_idx_xs;
        mpc_and_public(tio, yield, bit_in_word_idx_xs, share, 63, player);
        uint8_t public_bit_idx_eos = mpc_reconstruct(tio, yield, bit_in_word_idx_xs, 6);
        RegBS end_bit;
        mpc_get_bit(end_bit, word_eos, public_bit_idx_eos);
        RegBS value;
        mpc_and(tio, yield, value, Z, end_bit);
        Z = value;


        if (BITTRIE_DEBUG_ENABLED) {
            bool z_final = mpc_reconstruct(tio, yield, Z);
            if (player == 0) {
                if (z_final)
                    std::cout << "\nThe value " << searchArray[i] << " is present" << std::endl;
                else
                    std::cout << "\nThe value " << searchArray[i] << " is not present" << std::endl;
            }
        }
    }

    std::cout << "\n===== BitTrie Search Stats =====\n";
    tio.sync_lamport();
    mpcio.dump_stats(std::cout);
}
