// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// poll_driver_test.cpp — acceptance test for the photon (sampling) + wave
// (FPC voting / β-confidence) liveness layer. The headline property is the
// anti-toy one: an inconclusive round RESETS confidence, so a cumulative-counter
// stub (which would "decide" after β yes-rounds regardless of intervening
// disagreement) cannot pass scenario [2].

#include "lux/consensus2/photon.hpp"
#include "lux/consensus2/wave.hpp"

#include <cstdio>
#include <set>

using namespace lux::consensus2;

namespace {
int g_fail = 0;
void check(bool ok, const char* what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what); ++g_fail; }
}
}  // namespace

int main() {
    std::printf("============== consensus2 — photon + wave (liveness layer) ==============\n");
    std::printf("Lux family sampling + FPC confidence | no \"snow\" | reset-on-inconclusive\n\n");

    // K=5, alpha=0.8 → threshold = int(4.0) = 4 of 5; beta = 4 consecutive rounds.
    const WaveConfig cfg{/*k=*/5, /*alpha=*/0.8, /*beta=*/4};
    const Item item = [] { Item i{}; i[0] = 0xAB; i[1] = 0xCD; return i; }();  // wave keys on the full 32-byte id

    // [1] A virtuous run: 4 consecutive ACCEPT-supermajority rounds → Accept.
    {
        Wave w(cfg);
        check(w.threshold() == 4, "threshold = int(K*alpha) = 4");
        Decision d = Decision::Undecided;
        for (int r = 0; r < 3; ++r) d = w.record_round(item, 5, 5);
        check(d == Decision::Undecided, "undecided after 3 rounds (beta=4)");
        check(w.confidence(item) == 3, "confidence == 3 after 3 rounds");
        d = w.record_round(item, 5, 5);
        check(d == Decision::Accept, "ACCEPT after the 4th consecutive round");
        std::printf("[1/4] virtuous run reaches beta and decides Accept            => %s\n",
                    d == Decision::Accept ? "PASS" : "FAIL");
    }

    // [2] THE ANTI-TOY PROPERTY: 3 ACCEPT rounds, then ONE inconclusive round
    //     (yes=2,total=5 — neither side clears threshold 4) → confidence RESETS to
    //     0; the item is NOT decided even though ≥beta yes-rounds have now occurred.
    {
        Wave w(cfg);
        w.record_round(item, 5, 5);
        w.record_round(item, 5, 5);
        w.record_round(item, 5, 5);
        check(w.confidence(item) == 3, "confidence == 3 before the inconclusive round");
        Decision d = w.record_round(item, 2, 5);  // split vote → inconclusive
        check(w.confidence(item) == 0, "INCONCLUSIVE round RESETS confidence to 0");
        check(d == Decision::Undecided, "still undecided after the reset");
        // a cumulative-counter stub would now be at 4 and wrongly Accept.
        d = w.record_round(item, 5, 5);
        check(d == Decision::Undecided, "one good round after reset is not enough");
        check(w.confidence(item) == 1, "confidence rebuilds from 1");
        std::printf("[2/4] inconclusive round resets confidence (anti-toy)        => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [3] A preference switch resets confidence to 1 (not a continuation).
    {
        Wave w(cfg);
        w.record_round(item, 5, 5);
        w.record_round(item, 5, 5);
        w.record_round(item, 5, 5);          // confidence 3 for ACCEPT
        Decision d = w.record_round(item, 0, 5);  // REJECT-supermajority → switch
        check(w.confidence(item) == 1, "preference switch resets confidence to 1");
        check(d == Decision::Undecided, "switch does not instantly decide");
        std::printf("[3/4] preference switch resets confidence to 1               => %s\n",
                    w.confidence(item) == 1 ? "PASS" : "FAIL");
    }

    // [4] photon committee sampling: K distinct indices in range; deterministic
    //     per seed; different seeds differ.
    {
        const std::uint32_t n = 21, k = 5;
        auto a = photon::sample(n, k, /*seed=*/12345);
        auto a2 = photon::sample(n, k, /*seed=*/12345);
        auto b = photon::sample(n, k, /*seed=*/67890);
        check(a.size() == k, "sample returns exactly K members");
        std::set<std::uint32_t> uniq(a.begin(), a.end());
        check(uniq.size() == k, "sampled members are DISTINCT");
        bool in_range = true;
        for (auto x : a) in_range = in_range && (x < n);
        check(in_range, "sampled members are in [0, N)");
        check(a == a2, "same seed → same committee (deterministic)");
        check(a != b, "different seed → different committee");
        auto all = photon::sample(3, 9, /*seed=*/1);  // k > n clamps to n
        check(all.size() == 3, "K>N clamps to N");
        std::printf("[4/4] photon samples K distinct, in-range, deterministic     => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    std::printf("------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== POLL DRIVER: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== POLL DRIVER: 4/4 PASS ====\n");
    return 0;
}
