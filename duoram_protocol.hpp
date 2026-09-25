#pragma once

// The online algebra for the 3-party DUORAM protocol, expressed over GF(2)
// with 128-bit database words. Both addresses and database words use XOR
// shares in this project; address correction is the XOR permutation below.

#include "dpf.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <utility>
#include <stdexcept>
#include <vector>

namespace duoram {

using FlagVector = std::vector<uint8_t>;
using WordVector = std::vector<Block128>;

enum class DpfComponent : size_t {
  Read = 0,       // component (1) in the paper
  Blind0 = 1,      // component (2)
  Blind1 = 2       // component (3)
};

struct DpfShare {
  FlagVector flags;
  WordVector values;
  Block128 final_correction;
};

inline DpfShare make_dpf_share(DpfEvaluation evaluation) {
  return {std::move(evaluation.flags), std::move(evaluation.values),
          evaluation.final_correction};
}

struct PartyPreprocessing {
  uint64_t random_index_share = 0;
  std::array<DpfShare, 3> dpf;
};

struct HelperPreprocessing {
  // P2 holds only the component shares that the paper assigns to it.
  DpfShare party0_blind_component;
  DpfShare party1_blind_component;
};

struct ReadBlindShares {
  WordVector zeta0;
  WordVector zeta1;
};

struct BeaverAndTripleShare {
  Block128 x;
  Block128 y;
  Block128 z;
};

inline Block128 du_atallah_and_share(
    int party_id, const Block128& a_share, const Block128& b_share,
    const BeaverAndTripleShare& triple,
    const std::function<Block128(const Block128&)>& exchange_peer_block) {
  if (party_id != 0 && party_id != 1) {
    throw std::invalid_argument("Du–Atallah AND party_id must be 0 or 1");
  }
  if (!exchange_peer_block) {
    throw std::invalid_argument("Du–Atallah AND requires a peer exchange callback");
  }

  // These are the peer's masked inputs, not reconstructed openings.  This is
  // the Du–Atallah AND protocol for triples satisfying
  //   Z0=(X0&Y1)^T and Z1=(X1&Y0)^T.
  const Block128 peer_a_masked = exchange_peer_block(a_share ^ triple.x);
  const Block128 peer_b_masked = exchange_peer_block(b_share ^ triple.y);
  if (party_id == 0) {
    return (a_share & (b_share ^ peer_b_masked)) ^
           (triple.y & peer_a_masked) ^ triple.z;
  }
  return (a_share & (b_share ^ peer_b_masked)) ^
         (triple.y & peer_a_masked) ^ triple.z;
}

inline void require_same_size(size_t expected, size_t actual) {
  if (expected != actual) {
    throw std::invalid_argument("DUORAM vectors have inconsistent lengths");
  }
}

inline Block128 xor_dot(std::span<const Block128> words,
                        std::span<const uint8_t> flags) {
  require_same_size(words.size(), flags.size());
  Block128 result;
  for (size_t i = 0; i < words.size(); ++i) {
    if (flags[i] & 1U) {
      result ^= words[i];
    }
  }
  return result;
}

template <typename T>
std::vector<T> xor_permute(std::span<const T> input, uint64_t offset) {
  const size_t n = input.size();
  if (n == 0 || (n & (n - 1)) != 0 || offset >= n) {
    throw std::invalid_argument("DUORAM XOR permutation requires a power-of-two domain and in-range offset");
  }
  std::vector<T> output(n);
  for (size_t x = 0; x < n; ++x) {
    output[x ^ static_cast<size_t>(offset)] = input[x];
  }
  return output;
}

inline Block128 flag_product(const Block128& word, uint8_t flag) {
  return (flag & 1U) ? word : Block128{};
}

inline Block128 read_party0(std::span<const Block128> d0,
                            std::span<const Block128> blinded_d1,
                            std::span<const Block128> zeta0,
                            std::span<const uint8_t> t0_read,
                            std::span<const uint8_t> t0_blind1,
                            const Block128& gamma0) {
  const size_t n = d0.size();
  require_same_size(n, blinded_d1.size());
  require_same_size(n, zeta0.size());
  require_same_size(n, t0_read.size());
  require_same_size(n, t0_blind1.size());

  WordVector local_sum(n);
  FlagVector blind_correction(n);
  for (size_t i = 0; i < n; ++i) {
    local_sum[i] = d0[i] ^ blinded_d1[i];
    blind_correction[i] = t0_blind1[i] ^ t0_read[i];
  }
  return xor_dot(local_sum, t0_read) ^ xor_dot(zeta0, blind_correction) ^ gamma0;
}

inline Block128 read_party1(std::span<const Block128> d1,
                            std::span<const Block128> blinded_d0,
                            std::span<const Block128> zeta1,
                            std::span<const uint8_t> t1_read,
                            std::span<const uint8_t> t1_blind0,
                            const Block128& gamma1) {
  const size_t n = d1.size();
  require_same_size(n, blinded_d0.size());
  require_same_size(n, zeta1.size());
  require_same_size(n, t1_read.size());
  require_same_size(n, t1_blind0.size());

  WordVector local_sum(n);
  FlagVector blind_correction(n);
  for (size_t i = 0; i < n; ++i) {
    local_sum[i] = d1[i] ^ blinded_d0[i];
    blind_correction[i] = t1_blind0[i] ^ t1_read[i];
  }
  return xor_dot(local_sum, t1_read) ^ xor_dot(zeta1, blind_correction) ^ gamma1;
}

struct ReadCancellation {
  Block128 gamma0;
  Block128 gamma1;
};

inline ReadCancellation helper_read_cancellation(
    std::span<const Block128> zeta0, std::span<const uint8_t> t1_blind1,
    std::span<const Block128> zeta1, std::span<const uint8_t> t0_blind0,
    const Block128& rho) {
  return {xor_dot(zeta0, t1_blind1) ^ rho,
          xor_dot(zeta1, t0_blind0) ^ rho};
}

// Adds F & t to v elementwise. This is the GF(2) form of the paper's
// value-DPF correction (the 128-bit database word is the field element).
inline WordVector corrected_update_vector(std::span<const Block128> values,
                                          std::span<const uint8_t> flags,
                                          const Block128& final_correction) {
  require_same_size(values.size(), flags.size());
  WordVector result(values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    result[i] = values[i] ^ flag_product(final_correction, flags[i]);
  }
  return result;
}

struct Party0Update {
  WordVector database_delta;
  WordVector blind_delta;
  WordVector peer_blinded_delta;
};

struct Party1Update {
  WordVector database_delta;
  WordVector blind_delta;
  WordVector peer_blinded_delta;
};

inline Party0Update update_party0(const DpfShare& read_dpf,
                                 const DpfShare& blind_dpf,
                                 const DpfShare& peer_blind_dpf,
                                 const Block128& final_read,
                                 const Block128& final_blind,
                                 const Block128& final_peer_blind) {
  auto d = corrected_update_vector(read_dpf.values, read_dpf.flags, final_read);
  auto b = corrected_update_vector(blind_dpf.values, blind_dpf.flags, final_blind);
  auto p = corrected_update_vector(peer_blind_dpf.values, peer_blind_dpf.flags,
                                   final_peer_blind);
  require_same_size(d.size(), b.size());
  require_same_size(d.size(), p.size());

  Party0Update result{std::move(d), std::move(b), std::move(p)};
  for (size_t i = 0; i < result.database_delta.size(); ++i) {
    result.peer_blinded_delta[i] ^= result.database_delta[i];
  }
  return result;
}

inline Party1Update update_party1(const DpfShare& read_dpf,
                                 const DpfShare& blind_dpf,
                                 const DpfShare& peer_blind_dpf,
                                 const Block128& final_read,
                                 const Block128& final_blind,
                                 const Block128& final_peer_blind) {
  auto d = corrected_update_vector(read_dpf.values, read_dpf.flags, final_read);
  auto b = corrected_update_vector(blind_dpf.values, blind_dpf.flags, final_blind);
  auto p = corrected_update_vector(peer_blind_dpf.values, peer_blind_dpf.flags,
                                   final_peer_blind);
  require_same_size(d.size(), b.size());
  require_same_size(d.size(), p.size());

  Party1Update result{std::move(d), std::move(b), std::move(p)};
  for (size_t i = 0; i < result.peer_blinded_delta.size(); ++i) {
    result.peer_blinded_delta[i] ^= result.database_delta[i];
  }
  return result;
}

inline void helper_apply_blind_update(ReadBlindShares& blinds,
                                      const DpfShare& p0_blind_component,
                                      const DpfShare& p1_blind_component,
                                      const Block128& final_blind0,
                                      const Block128& final_blind1) {
  auto delta0 = corrected_update_vector(p0_blind_component.values,
                                        p0_blind_component.flags,
                                        final_blind0);
  auto delta1 = corrected_update_vector(p1_blind_component.values,
                                        p1_blind_component.flags,
                                        final_blind1);
  require_same_size(blinds.zeta0.size(), delta0.size());
  require_same_size(blinds.zeta1.size(), delta1.size());
  for (size_t i = 0; i < delta0.size(); ++i) {
    blinds.zeta0[i] ^= delta0[i];
    blinds.zeta1[i] ^= delta1[i];
  }
}

} // namespace duoram
