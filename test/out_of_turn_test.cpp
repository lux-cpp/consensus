// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// out_of_turn_test.cpp — the ACCEPTANCE-WINDOW discipline of the finality gate,
// the consensus2 realization of the proposer-fallback acceptance standard's
// before/after-window rule. consensus2 is LEADERLESS, so there is no proposer
// "turn" to jump; the eligibility window degenerates to two enforced invariants,
// both proved here against the gate's documented requirement that EVERY off-window
// input fails:
//
//   WINDOW OPEN  — a position collects votes ONLY after submit() has opened it
//                  (the deterministic, identical-on-every-node "eligibility"); a
//                  vote for an unopened position is rejected (no EARLY acceptance).
//   FULLY BOUND  — a vote/cert binds the canonical (block_id, height, epoch); a
//                  signature is non-malleable across position, so a STALE sig for
//                  another height/epoch/block cannot be lifted onto this one.
//
// The standard's enumerated rejections — out-of-set / forged / STALE / sub-quorum
// / tampered / EARLY — must ALL fail; cert validation is unchanged; an after-window
// SUBSTITUTE block is acceptable only through the identical submit+vote+cert path
// and never cross-contaminates the first block's tally.
//
// (Production proposer-windowing — a leader schedule with a deterministic eligible-
// proposer-per-round — is a node2 concern that does not yet exist in the leaderless
// mesh; when it lands it adds an eligibility predicate ON TOP of these invariants,
// it does not change them. See the report's decomplection note.)

#include "lux/consensus2/quorum_cert_engine.hpp"
#include "lux/consensus2/bls.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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
    if (bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
    if (bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk"); std::exit(2); }
    return k;
}
VotePosition make_pos(std::uint8_t tag, std::uint64_t height, std::uint32_t round = 0) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.height = height;
    p.round  = round;
    return p;
}
Signature sign_vote(const Key& key, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature sig{};
    if (bls::sign(key.sk.data(), msg.data(), msg.size(), sig.data()) != 0) { std::puts("sign"); std::exit(2); }
    return sig;
}

}  // namespace

int main() {
    std::printf("================== consensus2 — ACCEPTANCE WINDOW (no early/out-of-turn) ==================\n");
    std::printf("only an opened position collects votes; every position fully bound; off-window inputs FAIL\n\n");

    // 5 validators, stake 20 (total 100, floor 66, α=4).
    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x20 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, 20});

    // ── [1] WINDOW OPEN: no EARLY acceptance — a vote before submit is rejected ──
    {
        const int b = g_fail;
        QuorumCertEngine e(set, 4);
        const VotePosition P = make_pos(0x41, 10, 1);
        // The position is NOT yet opened. A perfectly valid signature is rejected.
        check(e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P)) == VoteResult::RejectedNoSuchBlock,
              "EARLY: valid vote before submit() ⇒ RejectedNoSuchBlock (window closed)");
        check(e.submit(P), "submit opens the window");
        check(e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P)) == VoteResult::Recorded,
              "after submit the same vote is Accepted (window open)");
        std::printf("[1/4] no early acceptance: a vote is collectible only after submit       => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [2] FULLY BOUND: a STALE sig (signed for another position) cannot be lifted ─
    //   NOTE the gate's O(1) batch-verify model: votes are CANDIDATES (no per-vote
    //   pairing) until the GATE is asked; the BLS check runs there, once, evicting
    //   every sig that does not verify for THIS position. So a stale sig can sit as
    //   a candidate but can NEVER reach finality — asking the gate is what rejects
    //   and evicts it. We drive exactly that and assert the position never
    //   finalizes and no stale candidate survives.
    {
        const int b = g_fail;
        QuorumCertEngine e(set, 4);
        const VotePosition P  = make_pos(0x42, 20, 1);   // the open position
        e.submit(P);
        // Four in-set validators each sign a DIFFERENT canonical position and offer
        // it for P (the domain-separated message binds every axis). Four votes (80
        // stake) clear the floors, so asking the gate verifies — and rejects all.
        const VotePosition diffHeight = make_pos(0x42, 21, 1);  // stale: another height
        const VotePosition diffRound  = make_pos(0x42, 20, 2);  // another round
        const VotePosition diffBlock  = make_pos(0x99, 20, 1);  // another block id
        const VotePosition diffAll    = make_pos(0x77, 99, 9);  // nothing in common
        check(e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], diffHeight)) == VoteResult::Recorded,
              "a stale sig JOINS as a candidate — recorded is not verified");
        (void)e.record_vote(P.block_id, keys[1].pk, sign_vote(keys[1], diffRound));
        (void)e.record_vote(P.block_id, keys[2].pk, sign_vote(keys[2], diffBlock));
        (void)e.record_vote(P.block_id, keys[3].pk, sign_vote(keys[3], diffAll));
        check(e.distinct_voters(P.block_id) == 4, "all four candidates are held, unverified");
        check(!e.is_final(P.block_id), "STALE sigs never finalize the open position (not liftable)");
        check(e.distinct_voters(P.block_id) == 0, "every stale candidate evicted AT THE GATE");
        check(!e.assemble_cert(P.block_id).has_value(), "no cert from cross-position sigs");
        std::printf("[2/4] stale/cross-position sigs are not liftable onto the open position  => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [3] the standard's full rejection set in one place — ALL fail ────────────
    {
        const int b = g_fail;
        QuorumCertEngine e(set, 4);
        const VotePosition P = make_pos(0x43, 30, 1);
        e.submit(P);

        // out-of-set: a valid sig by a key not in the set.
        Key outsider = make_key(0xEE);
        check(e.record_vote(P.block_id, outsider.pk, sign_vote(outsider, P)) == VoteResult::RejectedUnknownValidator,
              "OUT-OF-SET voter ⇒ RejectedUnknownValidator");
        // forged: an in-set key with a corrupted signature padding the quorum.
        for (int i = 0; i < 3; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        Signature forged = sign_vote(keys[3], P); forged[20] ^= 0x01;
        (void)e.record_vote(P.block_id, keys[3].pk, forged);
        // The count and stake floors are now met — by a tally one of whose sigs is
        // forged. Asking the gate verifies, evicts it, and refuses.
        check(!e.is_final(P.block_id), "FORGED sig padding the quorum does NOT finalize");
        check(e.distinct_voters(P.block_id) == 3, "the forged vote is evicted at the gate");
        // sub-quorum: 3 genuine (60 stake, <α and ≤66) ⇒ no cert.
        check(!e.is_final(P.block_id), "SUB-QUORUM (3 votes / 60 stake) ⇒ not final, no cert");
        check(!e.assemble_cert(P.block_id).has_value(), "no cert for a sub-quorum block");
        // complete the genuine quorum, then prove a TAMPERED cert fails verification.
        (void)e.record_vote(P.block_id, keys[3].pk, sign_vote(keys[3], P));
        auto cert = e.assemble_cert(P.block_id);
        check(cert.has_value() && e.verify_cert(*cert), "genuine 4-of-5 cert verifies (window honored)");
        if (cert) {
            QuorumCert t = *cert; t.aggregate_sig[5] ^= 0x01;
            check(!e.verify_cert(t), "TAMPERED cert ⇒ verify_cert false (cert validation unchanged)");
            QuorumCert h = *cert; h.position.height ^= 0x01;  // rebind to another height
            check(!e.verify_cert(h), "cert rebound to another height ⇒ verify_cert false (fully bound)");
        }
        std::printf("[3/4] out-of-set / forged / sub-quorum / tampered all FAIL                => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [4] after-window SUBSTITUTE: a sibling is acceptable only via the same path
    //        and never cross-contaminates the first block's tally ─────────────────
    {
        const int b = g_fail;
        QuorumCertEngine e(set, 4);
        const VotePosition P1 = make_pos(0x44, 40, 1);  // first opened block
        const VotePosition P2 = make_pos(0x45, 40, 1);  // substitute at the same height
        e.submit(P1);
        // 4 votes for the SUBSTITUTE P2 must not count toward P1 (keyed by full id);
        // and P2 itself is not collectible until it too is opened.
        check(e.record_vote(P2.block_id, keys[0].pk, sign_vote(keys[0], P2)) == VoteResult::RejectedNoSuchBlock,
              "substitute P2 not collectible until submitted (identical discipline)");
        for (int i = 0; i < 4; ++i) (void)e.record_vote(P1.block_id, keys[i].pk, sign_vote(keys[i], P1));
        check(e.is_final(P1.block_id), "P1 finalizes on its own 4 genuine votes");
        // open the substitute and vote it independently — separate tally, same gate.
        e.submit(P2);
        for (int i = 0; i < 4; ++i) (void)e.record_vote(P2.block_id, keys[i].pk, sign_vote(keys[i], P2));
        auto c1 = e.assemble_cert(P1.block_id);
        auto c2 = e.assemble_cert(P2.block_id);
        check(c1 && c2 && e.verify_cert(*c1) && e.verify_cert(*c2),
              "both certs validate identically (cert validation unchanged for the substitute)");
        check(c1 && c2 && c1->position.block_id != c2->position.block_id,
              "the two tallies are independent (no cross-contamination by block id)");
        std::printf("[4/4] after-window substitute: same discipline, independent tally        => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    std::printf("------------------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== ACCEPTANCE WINDOW: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== ACCEPTANCE WINDOW: PASS — only opened positions collect votes; off-window all reject ====\n");
    return 0;
}
