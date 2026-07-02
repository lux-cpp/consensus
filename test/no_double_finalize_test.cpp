// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// no_double_finalize_test.cpp — the BFT SAFETY proof consensus2 was missing:
// under fewer than n/3 Byzantine stake, no two CONFLICTING blocks can finalize at
// one height. This is the agreement half of "BFT ≥ avalanche". It is proved at
// three altitudes, each with REAL BLS12-381 keys and signatures (a real violation
// would reproduce here, not be argued away):
//
//   [1] GATE / combinatorial   — quorum intersection. Two >2/3-stake certs for
//       conflicting blocks must share > 1/3 stake of DOUBLE-voters. With ≤ ⌊n/3⌋
//       equivocators NO honest split yields two certs (exhaustively enumerated);
//       with ⌈n/3⌉ equivocators it becomes possible — so the bound is TIGHT and
//       equals avalanche's f < n/3 (this is the documented BFT limit, not a bug).
//
//   [2] NODE / discipline      — an honest Node fed BOTH siblings to a β-confirmed
//       ACCEPT signs EXACTLY ONE: the per-HEIGHT non-equivocation guard makes an
//       honest validator's stake land in at most one quorum per height. This is the
//       premise [1] relies on; without it [3] (and real safety) collapses.
//
//   [3] EMERGENT / multi-node  — the real protocol: 10 nodes, 3 Byzantine
//       equivocators (f = 3 < 10/3) driving two branches over a vote bus. Every
//       honest node independently commits the SAME single head; the second branch
//       never finalizes anywhere. The emergent property, asserted — not mocked.
//
//   [4] LIFECYCLE / height-only + finalize-then-resign — the two safety properties
//       the slot's KEY and LIFECYCLE must have. (a) A DIFFERENT-EPOCH sibling at the
//       same height is refused (the slot is HEIGHT-ONLY; epoch is a proposer-chosen
//       axis that must not fragment it). (b) After a height is decided, a sibling
//       there is refused BOTH while the slot is retained AND after it is GC'd — the
//       durable decided-height gate closes the prune-then-resign fork. A higher open
//       height stays signable (no liveness loss).
//
// Teeth (mutation-verified, see proofs/no_double_finalize.tex and the report):
//   - delete the Node non-equivocation guard ⇒ [2] sees two broadcasts and [3]
//     finalizes BOTH branches with only f=3 Byzantine (safety violated). RED.
//   - key the slot per-block_id, or per-(height,epoch) instead of per-HEIGHT ⇒ [4a]
//     signs both same-height siblings (a different-epoch sibling opens a second slot),
//     the exact fresh-net double-finalization. RED.
//   - erase the just-decided height's slot AND drop the decided-height gate (the
//     inclusive-prune-no-gate pre-fix state) ⇒ [4b] signs the sibling after the GC. RED.
//   - [1] is self-witnessing: it asserts BOTH sides of the boundary (f=3 cannot
//     double-finalize; f=4 can). Any change lowering the effective quorum below
//     7-of-10 (α OR the 2/3 stake floor — uniform stake makes them coincide at 7
//     here) flips the f=3 case to a double-finalize. The stake floor's independence
//     from the count gate is separately mutation-proven in toy_stub_killer [4].

#include "lux/consensus2/node.hpp"
#include "lux/consensus2/quorum_cert_engine.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace lux::consensus2;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

struct Key { std::array<std::uint8_t, 32> sk{}; PubKey pk{}; };
Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk"); std::exit(2); }
    return k;
}
VotePosition make_pos(std::uint8_t tag, std::uint64_t height, std::uint64_t epoch) {
    VotePosition p{}; p.block_id.fill(tag); p.height = height; p.epoch = epoch; return p;
}
Signature sign_vote(const Key& key, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature sig{};
    if (cevm::crypto::bls::sign(key.sk.data(), msg.data(), msg.size(), sig.data()) != 0) { std::puts("sign"); std::exit(2); }
    return sig;
}

// In-process vote bus; counts broadcasts (used by [2] to observe equivocation).
struct Bus : VoteTransport {
    std::vector<Node*> subs;
    std::vector<SignedVote> broadcasts;
    void broadcast(const SignedVote& v) override {
        broadcasts.push_back(v);
        for (Node* n : subs) n->onVote(v);
    }
};

}  // namespace

int main() {
    std::printf("=================== consensus2 — NO DOUBLE FINALIZE (BFT safety) ===================\n");
    std::printf("under f < n/3, two conflicting blocks never both finalize at one height (real BLS)\n\n");

    // 10 validators, stake 10 each → total 100, floor(2/3·100)=66, α=7.
    // 7 distinct voters (70) finalize; 6 (60) do not. Double-finalize needs
    // ≥ 2·7−10 = 4 equivocators (40 stake > ⌊100/3⌋=33) — exactly f ≥ ⌈n/3⌉.
    constexpr std::uint32_t kN = 10, kAlpha = 7;
    constexpr std::uint64_t kStake = 10;
    std::vector<Key> keys;
    for (std::uint32_t i = 0; i < kN; ++i) keys.push_back(make_key(std::uint8_t(0xC0 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, kStake});
    check(two_thirds_stake_floor(kN * kStake) == 66, "floor(2/3·100) == 66");

    // ── [1] GATE quorum-intersection: tight at f = n/3 ───────────────────────────
    // B1,B2 are CONFLICTING siblings (same height+epoch, different id). Equivocators
    // sign BOTH; honest validators sign at most one. Build a fresh engine per case.
    {
        const int b = g_fail;
        const VotePosition B1 = make_pos(0xB1, 5, 1);
        const VotePosition B2 = make_pos(0xB2, 5, 1);

        // record a list of (key index, block) votes into a fresh engine, return it.
        auto run = [&](const std::vector<std::pair<std::uint32_t, const VotePosition*>>& votes) {
            auto e = std::make_unique<QuorumCertEngine>(set, kAlpha);
            e->submit(B1); e->submit(B2);
            for (auto& [ki, b] : votes)
                (void)e->record_vote(b->block_id, keys[ki].pk, sign_vote(keys[ki], *b));
            return e;
        };

        // f = 3 equivocators (indices 0,1,2 sign BOTH). EXHAUSTIVELY enumerate every
        // honest split of the 7 honest validators (3..9) across B1/B2 and assert that
        // NO split finalizes both — the agreement property at f = ⌊n/3⌋ = 3.
        bool ever_both = false, some_single = false;
        for (std::uint32_t hb1 = 0; hb1 <= 7; ++hb1) {
            std::vector<std::pair<std::uint32_t, const VotePosition*>> votes;
            for (std::uint32_t e = 0; e < 3; ++e) { votes.push_back({e, &B1}); votes.push_back({e, &B2}); }
            // first hb1 honest validators → B1, the rest → B2 (each honest signs ONE).
            for (std::uint32_t h = 0; h < 7; ++h)
                votes.push_back({3 + h, (h < hb1) ? &B1 : &B2});
            auto e = run(votes);
            const bool f1 = e->is_final(B1.block_id), f2 = e->is_final(B2.block_id);
            if (f1 && f2) ever_both = true;
            if (f1 != f2) some_single = true;
        }
        check(!ever_both, "f=3: NO honest split finalizes both branches (agreement holds)");
        check(some_single, "f=3: at least one split commits a single head (liveness not vacuous)");

        // f = 4 equivocators (0..3 sign BOTH) + honest 3/3 split ⇒ BOTH reach 7 (70).
        // Demonstrates the bound is TIGHT: ⌈n/3⌉ equivocators CAN double-finalize.
        {
            std::vector<std::pair<std::uint32_t, const VotePosition*>> votes;
            for (std::uint32_t e = 0; e < 4; ++e) { votes.push_back({e, &B1}); votes.push_back({e, &B2}); }
            for (std::uint32_t h = 4; h < 7; ++h) votes.push_back({h, &B1});   // 3 honest → B1
            for (std::uint32_t h = 7; h < 10; ++h) votes.push_back({h, &B2});  // 3 honest → B2
            auto e = run(votes);
            check(e->is_final(B1.block_id) && e->is_final(B2.block_id),
                  "f=4: ⌈n/3⌉ equivocators CAN double-finalize — bound is exactly avalanche's n/3");
        }
        std::printf("[1/3] gate quorum-intersection: f=3 safe (exhaustive), f=4 breaks (tight) => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [2] NODE non-equivocation: one honest node, two siblings, ONE vote ───────
    {
        const int b = g_fail;
        Bus bus;
        Node node(0, keys[0].sk, keys[0].pk, set, kAlpha, WaveConfig{5, 0.8, 4}, 1, bus);
        bus.subs.push_back(&node);
        const VotePosition B1 = make_pos(0xB1, 9, 1);
        const VotePosition B2 = make_pos(0xB2, 9, 1);  // sibling: same (height,epoch)
        node.submit(B1); node.submit(B2);

        // Drive B1 to a β-confirmed ACCEPT (it commits slot (9,1)→B1 and broadcasts),
        // THEN drive B2 to a β-confirmed ACCEPT. An honest node must REFUSE B2.
        for (int r = 0; r < 4; ++r) node.poll(B1, 5, 5);
        for (int r = 0; r < 4; ++r) node.poll(B2, 5, 5);

        check(bus.broadcasts.size() == 1, "honest node broadcasts EXACTLY ONE vote for the slot");
        check(!bus.broadcasts.empty() && bus.broadcasts[0].block_id == B1.block_id,
              "the single vote is for B1 (the first slot commitment), never the sibling B2");
        // and its own gate reflects only the one self-vote (1 distinct voter each).
        check(node.cert(B1.block_id).has_value() == false, "no cert yet (only its own 1 vote)");
        std::printf("[2/3] honest node fed two siblings signs exactly one (non-equivocation) => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [3] EMERGENT: 10 nodes, f=3 equivocators, single head on every honest node ─
    {
        const int b = g_fail;
        // 7 honest Nodes (indices 3..9) on one bus; keys 0..2 are Byzantine (no Node).
        Bus bus;
        std::vector<std::unique_ptr<Node>> honest;
        for (std::uint32_t i = 3; i < kN; ++i)
            honest.push_back(std::make_unique<Node>(i, keys[i].sk, keys[i].pk, set, kAlpha,
                                                    WaveConfig{5, 0.8, 4}, 1, bus));
        for (auto& n : honest) bus.subs.push_back(n.get());

        const VotePosition B1 = make_pos(0xB1, 12, 1);
        const VotePosition B2 = make_pos(0xB2, 12, 1);
        for (auto& n : honest) { n->submit(B1); n->submit(B2); }

        // Adversarial sampler pushes BOTH siblings to every honest node. The per-slot
        // guard forces each to commit ONE: nodes 3..6 reach B1 first (→B1), nodes
        // 7..9 reach B2 first (→B2). WITHOUT the guard each would vote BOTH.
        for (std::size_t idx = 0; idx < honest.size(); ++idx) {
            Node* n = honest[idx].get();
            const bool prefersB1 = idx < 4;  // first 4 honest → B1, last 3 → B2
            const VotePosition& first  = prefersB1 ? B1 : B2;
            const VotePosition& second = prefersB1 ? B2 : B1;
            for (int r = 0; r < 4; ++r) n->poll(first, 5, 5);   // commit this slot
            for (int r = 0; r < 4; ++r) n->poll(second, 5, 5);  // guard refuses the sibling
        }

        // The 3 Byzantine validators equivocate: each injects a valid vote for BOTH
        // branches into every honest gate (this is what a real equivocator does —
        // it does not run the honest Node, it just emits two signed votes).
        for (std::uint32_t b = 0; b < 3; ++b) {
            SignedVote v1{B1.block_id, keys[b].pk, sign_vote(keys[b], B1)};
            SignedVote v2{B2.block_id, keys[b].pk, sign_vote(keys[b], B2)};
            bus.broadcast(v1);
            bus.broadcast(v2);
        }

        // Tally on every honest gate: B1 = 4 honest + 3 Byz = 7 (70>66) → FINAL;
        // B2 = 3 honest + 3 Byz = 6 (60≤66) → NOT final. Exactly one head, everywhere.
        bool all_b1 = true, none_b2 = true, certs_agree = true;
        std::optional<QuorumCert> head;
        for (auto& n : honest) {
            all_b1  &= n->isFinal(B1.block_id);
            none_b2 &= !n->isFinal(B2.block_id);
            auto c = n->cert(B1.block_id);
            if (!c || !n->verifyCert(*c)) certs_agree = false;
            else if (!head) head = c;
            else if (c->voters != head->voters) certs_agree = false;
        }
        check(all_b1, "every honest node finalizes the single head B1");
        check(none_b2, "NO honest node finalizes the conflicting branch B2");
        check(certs_agree, "all honest nodes assemble the IDENTICAL verifying cert (single head)");
        check(head.has_value() && head->voters.size() == kAlpha && head->voted_stake == kAlpha * kStake,
              "the head cert carries exactly 7 voters / 70 stake (4 honest + 3 Byzantine)");
        std::printf("[3/3] 10 nodes, 3 equivocators (f<n/3): exactly one head commits      => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [4] LIFECYCLE: height-only slot + finalize-then-resign ───────────────────
    {
        const int b = g_fail;

        // [4a] DIFFERENT-EPOCH sibling at the SAME height must be refused. The slot is
        // HEIGHT-ONLY; the epoch is a proposer-chosen axis (a bare/pre-fork block and a
        // wrapped one at one height carry different epochs). Under the pre-fix
        // (height,epoch) slot, B2 would open a SECOND slot and be signed — two α/⅔ certs
        // at one height, the fresh-net fatal.
        {
            Bus bus;
            Node node(0, keys[0].sk, keys[0].pk, set, kAlpha, WaveConfig{5, 0.8, 4}, 1, bus);
            bus.subs.push_back(&node);
            const VotePosition B1 = make_pos(0xB1, 9, 1);
            const VotePosition B2 = make_pos(0xB2, 9, 2);  // SAME height, DIFFERENT epoch
            node.submit(B1); node.submit(B2);
            for (int r = 0; r < 4; ++r) node.poll(B1, 5, 5);  // commit height 9 → B1
            for (int r = 0; r < 4; ++r) node.poll(B2, 5, 5);  // must REFUSE (height 9 taken)
            check(bus.broadcasts.size() == 1,
                  "[4a] height-only slot: a different-EPOCH sibling at the same height is refused");
            check(!bus.broadcasts.empty() && bus.broadcasts[0].block_id == B1.block_id,
                  "[4a] the single vote is for B1, never the different-epoch sibling B2");
        }

        // [4b] FINALIZE-THEN-RESIGN: after height H is decided, a sibling there is refused
        // BOTH while the slot is retained AND after it is GC'd by a higher finalize — the
        // durable decided-height gate. A higher OPEN height stays signable.
        {
            Bus bus;
            Node node(0, keys[0].sk, keys[0].pk, set, kAlpha, WaveConfig{5, 0.8, 4}, 1, bus);
            bus.subs.push_back(&node);
            const VotePosition A    = make_pos(0xA1, 20, 1);  // the winner at height 20
            const VotePosition Bsib = make_pos(0xB2, 20, 2);  // losing sibling at 20 (diff id+epoch)
            const VotePosition C    = make_pos(0xC3, 22, 1);  // a higher, still-open height
            node.submit(A); node.submit(Bsib); node.submit(C);

            for (int r = 0; r < 4; ++r) node.poll(A, 5, 5);   // commit height 20 → A (1 broadcast)
            check(bus.broadcasts.size() == 1, "[4b] node signs the winner A at height 20");

            // Height 20 is decided. GC is STRICTLY BELOW 20, so slot{20} is retained (belt);
            // the decided-height gate refuses height 20 regardless (durable).
            node.mark_finalized_through(20);
            for (int r = 0; r < 4; ++r) node.poll(Bsib, 5, 5);
            check(bus.broadcasts.size() == 1,
                  "[4b] sibling at the just-decided height 20 is refused (gate + retained slot)");

            // Advance the frontier to 21: slot{20} is now GC'd. ONLY the decided-height gate
            // protects height 20 — the sibling must STILL be refused (prune-then-resign closed).
            node.mark_finalized_through(21);
            for (int r = 0; r < 4; ++r) node.poll(Bsib, 5, 5);
            check(bus.broadcasts.size() == 1,
                  "[4b] sibling refused at decided height 20 even AFTER its slot is GC'd (durable gate)");

            // A higher OPEN height (22 > frontier 21) remains signable — no liveness loss.
            for (int r = 0; r < 4; ++r) node.poll(C, 5, 5);
            check(bus.broadcasts.size() == 2 && bus.broadcasts.back().block_id == C.block_id,
                  "[4b] a height above the decided frontier is still signable (gate never stalls progress)");
        }

        std::printf("[4/4] height-only slot + finalize-then-resign: sibling refused, tip signable => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    std::printf("-----------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== NO DOUBLE FINALIZE: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== NO DOUBLE FINALIZE: PASS — agreement holds at f<n/3, tight at n/3 ====\n");
    return 0;
}
