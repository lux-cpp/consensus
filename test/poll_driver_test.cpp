// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// poll_driver_test.cpp — acceptance test for the photon (sampling) + wave
// (FPC voting / β-confidence) liveness layer. The headline property is the
// anti-toy one: an inconclusive round RESETS confidence, so a cumulative-counter
// stub (which would "decide" after β yes-rounds regardless of intervening
// disagreement) cannot pass scenario [2].

#include "lux/consensus/photon.hpp"
#include "lux/consensus/wave.hpp"

#include <cstdio>
#include <set>
#include <stdexcept>

using namespace lux::consensus;

namespace {
int g_fail = 0;
void check(bool ok, const char* what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what); ++g_fail; }
}
}  // namespace

int main() {
    std::printf("============== consensus — photon + wave (liveness layer) ==============\n");
    std::printf("Lux family sampling + FPC confidence | no \"snow\" | reset-on-inconclusive\n\n");

    // K=5, threshold = 4 of 5; beta = 4 consecutive rounds.
    const WaveConfig cfg{/*k=*/5, /*threshold=*/4, /*beta=*/4};
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
        std::printf("[1/10] virtuous run reaches beta and decides Accept            => %s\n",
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
        std::printf("[2/10] inconclusive round resets confidence (anti-toy)        => %s\n",
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
        // …and back again. A switch is not a one-way door: a node that could only
        // ever move from Accept to Reject would latch on the first disagreement it
        // saw and never rejoin a network that went the other way.
        w.record_round(item, 0, 5);               // confidence 2 for REJECT
        check(w.confidence(item) == 2, "REJECT confirms consecutively too");
        d = w.record_round(item, 5, 5);           // ACCEPT-supermajority → switch back
        check(w.confidence(item) == 1, "and switching BACK to Accept restarts at 1");
        check(d == Decision::Undecided, "the switch back does not decide either");
        std::printf("[3/10] preference switch resets confidence to 1               => %s\n",
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
        std::printf("[4/10] photon samples K distinct, in-range, deterministic     => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [5] The tally is CLAMPED to the committee, and that is what keeps "exactly
    //     one side can be strong" true. The constructor's majority guard is
    //     threshold·2 > k; it says nothing about a total larger than k. With k=5
    //     and threshold=4, an over-reported round of 5 yes out of 9 would make
    //     yes_strong (5≥4) AND no_strong (9−5=4≥4) at once — two preferences from
    //     one round. Clamping total to k first is what makes the guard hold
    //     unconditionally, against a sampler that reports more responses than it
    //     asked for.
    {
        Wave w(cfg);
        Decision d = w.record_round(item, 5, 9);
        check(w.confidence(item) == 1, "an over-reported total clamps to k, and one side wins");
        check(d == Decision::Undecided, "one round is not beta");
        for (int r = 0; r < 3; ++r) d = w.record_round(item, 5, 9);
        check(d == Decision::Accept, "the clamped rounds accumulate toward the SAME preference");
        std::printf("[5/10] a total above K is clamped, so only one side can be strong => %s\n",
                    d == Decision::Accept ? "PASS" : "FAIL");
    }

    // [6] A tally cannot exceed its own total, and a round with no responses is
    //     not a round. Neither may disturb state a real round built.
    {
        Wave w(cfg);
        w.record_round(item, 5, 5);
        w.record_round(item, 5, 5);
        check(w.confidence(item) == 2, "two consecutive ACCEPT rounds");
        Decision d = w.record_round(item, 0, 0);
        check(w.confidence(item) == 2, "an empty round changes nothing");
        check(d == Decision::Undecided, "and decides nothing");
        d = w.record_round(item, 7, 5);
        check(w.confidence(item) == 3, "yes above total is clamped to total, still ACCEPT-strong");
        check(d == Decision::Undecided, "still short of beta");
        std::printf("[6/10] yes>total clamps; a zero-response round is a no-op       => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [7] REJECT is a decision, reached the same way ACCEPT is: consecutive
    //     confirmation to β, and then latched. A rung that could only ever decide
    //     one way is not a decision procedure.
    {
        const WaveConfig two{/*k=*/5, /*threshold=*/4, /*beta=*/2};
        Wave w(two);
        Decision d = w.record_round(item, 0, 5);
        check(w.confidence(item) == 1, "one REJECT-supermajority round establishes the preference");
        check(d == Decision::Undecided, "one round is not beta");
        d = w.record_round(item, 1, 5);
        check(d == Decision::Reject, "the second consecutive REJECT round decides Reject");
        check(w.decision(item) == Decision::Reject, "and the decision is readable after the fact");
        d = w.record_round(item, 5, 5);
        check(d == Decision::Reject, "a decision is LATCHED — a later ACCEPT round cannot reopen it");
        std::printf("[7/10] consecutive REJECT rounds decide, and the decision latches => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [8] An item nobody has polled has no opinion and no confidence — the read
    //     side is fail-closed in the same way the write side is.
    {
        Wave w(cfg);
        const Item unseen = [] { Item i{}; i[0] = 0xFF; return i; }();
        check(w.decision(unseen) == Decision::Undecided, "an unpolled item is Undecided");
        check(w.confidence(unseen) == 0, "an unpolled item carries no confidence");
        w.record_round(item, 5, 5);
        check(w.decision(item) == Decision::Undecided, "a polled but undecided item is still Undecided");
        check(w.decision(unseen) == Decision::Undecided, "and polling one item says nothing about another");
        std::printf("[8/10] an unpolled item is Undecided with zero confidence       => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [9] The config a live network runs is DERIVED from n, and every parameter it
    //     could be built with that cannot decide safely is refused at construction.
    //     The last of those is the one that matters: a threshold at or below half
    //     the committee lets ACCEPT and REJECT both clear it in a single round.
    {
        const WaveConfig small = WaveConfig::feasible(2);
        check(small.k == kMinBFTCommittee,
              "a set below the minimum Byzantine committee still samples that many");
        check(small.threshold == two_thirds_count(kMinBFTCommittee) && small.beta == kFeasibleBeta,
              "and takes the strict-two-thirds count over that committee");
        const WaveConfig big = WaveConfig::feasible(21);
        check(big.k == 21 && big.threshold == two_thirds_count(21),
              "a set at or above it samples itself");

        // Every parameter feasible() cannot produce, refused.
        const auto refuses = [](WaveConfig c) {
            try { Wave w(c); } catch (const std::invalid_argument&) { return true; }
            return false;
        };
        check(refuses(WaveConfig{/*k=*/0, /*threshold=*/1, /*beta=*/2}), "k of zero is refused");
        check(refuses(WaveConfig{/*k=*/5, /*threshold=*/4, /*beta=*/0}), "beta of zero is refused");
        check(refuses(WaveConfig{/*k=*/5, /*threshold=*/0, /*beta=*/2}), "a threshold of zero is refused");
        check(refuses(WaveConfig{/*k=*/5, /*threshold=*/6, /*beta=*/2}), "a threshold above k is refused");
        check(refuses(WaveConfig{/*k=*/6, /*threshold=*/3, /*beta=*/2}),
              "a threshold at half of k is refused — both sides could clear it in one round");
        check(!refuses(WaveConfig{/*k=*/5, /*threshold=*/3, /*beta=*/2}),
              "and a strict majority of k is accepted");
        std::printf("[9/10] feasible() derives the committee; unsafe configs refused => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // [10] Drawing from an empty set draws nothing, and asking for an index below
    //      zero candidates yields none. Both are the guard on a modulo that would
    //      otherwise divide by zero.
    {
        check(photon::sample(0, 5, /*seed=*/7).empty(), "no committee is drawn from an empty set");
        check(photon::sample(0, 0, /*seed=*/7).empty(), "and none from an empty request either");
        photon::Rng rng(42);
        check(rng.below(0) == 0, "an index below zero candidates is zero, not a division by zero");
        check(rng.below(1) == 0, "and below one candidate it is that candidate");
        std::printf("[10/10] an empty set yields an empty committee                  => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    std::printf("------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== POLL DRIVER: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== POLL DRIVER: 10/10 PASS ====\n");
    return 0;
}
