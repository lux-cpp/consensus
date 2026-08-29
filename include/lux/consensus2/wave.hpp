// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// wave.hpp — threshold voting with confidence accumulation (FPC). The Lux
// consensus family's voting+confidence stage: each round samples K peers
// (photon), tallies ACCEPT vs total, and on a ≥ K·α supermajority advances a
// consecutive-success counter (focus's β counter). An INCONCLUSIVE round resets
// the counter to zero — the property a naive cumulative counter gets wrong.
// Decide when the counter reaches β; a preference switch resets it to one.
//
// Ported from luxfi/consensus protocol/wave (+ protocol/focus). Matches the
// semantics of wave.Tick exactly: threshold = ceil(K·α) (threshold.hpp's
// alpha_threshold — the SAME function both sides call), consecutive-or-reset.
//
// This is the LIVENESS / preference layer — which item the network is converging
// on. It carries NO cryptographic weight. Final, cryptographic safety (a signed
// > 2/3-stake quorum certificate) is the separate concern of QuorumCertEngine:
// wave decides "accept this item"; the gate proves it with real BLS + stake.

#pragma once

#include "lux/consensus2/threshold.hpp"

#include <array>
#include <cstdint>
#include <map>

namespace lux::consensus2 {

enum class Decision : std::uint8_t { Undecided = 0, Accept = 1, Reject = 2 };

// β for a set sized by feasible() — Go config.FeasibleParams sets Beta=2: one
// confirming round of hysteresis, so a transient one-round majority flip cannot
// decide, without the fragility of a deep β at zero margin.
inline constexpr std::uint32_t kFeasibleBeta = 2;

struct WaveConfig {
    std::uint32_t k = 21;                       // committee sample size per round
    double alpha = kConsensusSuperMajority;     // threshold = ceil(k·alpha)
    std::uint32_t beta = kFeasibleBeta;         // consecutive rounds required to decide

    // The parameter set a live network of n validators runs — Go
    // config.FeasibleParams(n): K = max(n, minimal BFT committee), α = the
    // equal-stake strict-⅔ count as a ratio of K, β = 2. Sizing the committee here
    // rather than at each call site is what keeps the sampling threshold and the
    // stake predicate one decision.
    [[nodiscard]] static WaveConfig feasible(std::uint32_t n) noexcept;
};

// An item is keyed by the FULL 32-byte block id — never a lossy prefix. Keying on
// a truncated handle would let an adversary grind a colliding id to cross-
// contaminate one block's confidence with another's polls (red M4). The key is
// the raw 32 bytes; the poll layer still carries no crypto dependency (it neither
// signs nor verifies — it only compares ids for equality).
using Item = std::array<std::uint8_t, 32>;

class Wave {
public:
    explicit Wave(WaveConfig cfg);

    // Apply one poll round's tally for `item`: `yes` ACCEPT votes out of `total`
    // sampled responses. Returns the decision so far (Undecided until β reached,
    // then latched). Mirrors wave.Tick:
    //   threshold = int(k·alpha)
    //   yes ≥ threshold            → prefer Accept
    //   (total − yes) ≥ threshold  → prefer Reject
    //   otherwise                  → reset count to 0  (inconclusive)
    //   same preference as last    → count++   (consecutive confirmation)
    //   preference switched        → count = 1
    //   count ≥ beta               → decide (latched)
    Decision record_round(const Item & item, std::uint32_t yes, std::uint32_t total);

    Decision decision(const Item & item) const;
    std::uint32_t confidence(const Item & item) const;  // current consecutive count
    int threshold() const noexcept { return threshold_; }

private:
    struct State {
        bool pref = false;        // current preference (meaningful once have_pref)
        bool have_pref = false;   // a preference has been established
        std::uint32_t count = 0;  // consecutive same-preference supermajority rounds
        Decision result = Decision::Undecided;
        bool decided = false;     // latched once count reaches beta
    };

    WaveConfig cfg_;
    int threshold_;
    std::map<Item, State> states_;  // std::map: total order on the 32-byte id, no hash needed
};

}  // namespace lux::consensus2
