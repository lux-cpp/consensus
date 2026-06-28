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
// semantics of wave.Tick exactly (threshold = int(K·α); consecutive-or-reset).
//
// This is the LIVENESS / preference layer — which item the network is converging
// on. It carries NO cryptographic weight. Final, cryptographic safety (a signed
// > 2/3-stake quorum certificate) is the separate concern of QuorumCertEngine:
// wave decides "accept this item"; the gate proves it with real BLS + stake.

#pragma once

#include <cstdint>
#include <unordered_map>

namespace lux::consensus2 {

enum class Decision : std::uint8_t { Undecided = 0, Accept = 1, Reject = 2 };

struct WaveConfig {
    std::uint32_t k = 21;        // committee sample size per round
    double alpha = 0.69;         // supermajority fraction; threshold = int(k·alpha)
    std::uint32_t beta = 15;     // consecutive successful rounds required to decide
};

// One item == one thing being voted on (e.g. a block id reduced to a handle).
// Kept decoupled from BlockId so the poll layer has no crypto dependency.
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
    Decision record_round(std::uint64_t item, std::uint32_t yes, std::uint32_t total);

    Decision decision(std::uint64_t item) const;
    std::uint32_t confidence(std::uint64_t item) const;  // current consecutive count
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
    std::unordered_map<std::uint64_t, State> states_;
};

}  // namespace lux::consensus2
