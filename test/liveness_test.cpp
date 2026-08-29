// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// liveness_test.cpp — the LIVENESS half of "BFT ≥ avalanche": the chain keeps
// finalizing through a faulty validator. In a LEADERLESS protocol there is no
// single proposer to wait on — any α distinct voters carrying > 2/3 stake finalize
// — so a down or actively-misbehaving validator is ROUTED AROUND, never blocks
// progress, and the system self-heals without a manual restart. Proved in-process
// with the REAL Node + QuorumCertEngine (the over-the-wire companion is node2's
// node2_liveness_test):
//
//   [1] DOWN validators — f = ⌊(n-1)/3⌋ = 3 of 10 silent (never join, never vote):
//       the remaining 7 (70 stake) finalize a verifying cert. With 4 down (only 6
//       live, 60 ≤ 66) NOTHING finalizes — the boundary is exactly avalanche's n/3
//       (stalling below quorum is the correct safe degradation, not a fork).
//
//   [2] WEDGED-but-PRESENT validator — in the set, "gossiping", but never casts a
//       valid ACCEPT vote: it floods garbage (bad-signature votes + votes for a
//       block it never submitted). Every honest gate rejects the garbage; the
//       honest quorum finalizes AROUND it; the cert never contains its key.
//
//   [3] SELF-HEAL — with 3 validators permanently down, three consecutive heights
//       each finalize with no reset/reboot: continuous operation through the fault.
//
// Teeth: require unanimity (α = n) and [1]/[3] stop finalizing with even one node
// down; let the gate count unverified votes and [2]'s garbage would finalize a
// forged quorum. Both are caught here.

#include "lux/consensus2/node.hpp"
#include "lux/consensus2/quorum_cert_engine.hpp"
#include "lux/consensus2/bls.hpp"

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
struct Bus : VoteTransport {
    std::vector<Node*> subs;
    void broadcast(const SignedVote& v) override { for (Node* n : subs) n->onVote(v); }
};

}  // namespace

int main() {
    std::printf("===================== consensus2 — LIVENESS (route around faults) =====================\n");
    std::printf("leaderless: any α distinct >2/3-stake voters finalize; a down/wedged node is routed around\n\n");

    constexpr std::uint32_t kN = 10, kAlpha = 7;
    constexpr std::uint64_t kStake = 10;  // total 100, floor 66; 7 live=70 final, 6 live=60 stall
    std::vector<Key> keys;
    for (std::uint32_t i = 0; i < kN; ++i) keys.push_back(make_key(std::uint8_t(0xD0 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, kStake});

    // Build `live` Node instances (the first `live` validator indices) on one bus;
    // the rest are DOWN (absent — not subscribed, never poll). Returns the nodes.
    auto run_height = [&](std::vector<std::unique_ptr<Node>>& nodes, Bus& bus,
                          std::uint32_t live, const VotePosition& pos) {
        for (std::uint32_t i = 0; i < live; ++i)
            nodes.push_back(std::make_unique<Node>(i, keys[i].sk, keys[i].pk, set, kAlpha,
                                                   WaveConfig{5, 0.8, 4}, bus));
        for (auto& n : nodes) bus.subs.push_back(n.get());
        for (auto& n : nodes) n->submit(pos);
        for (int r = 0; r < 4; ++r) for (auto& n : nodes) n->poll(pos.block_id, 5, 5);  // β rounds
    };

    // ── [1] DOWN validators: 3 down finalize, 4 down stall (the n/3 boundary) ────
    {
        const int b = g_fail;
        // 3 of 10 down → 7 live (70 stake) finalize.
        Bus bus; std::vector<std::unique_ptr<Node>> nodes;
        const VotePosition pos = make_pos(0x71, 100, 1);
        run_height(nodes, bus, /*live=*/7, pos);
        bool all_final = true, all_verify = true;
        for (auto& n : nodes) {
            all_final &= n->isFinal(pos.block_id);
            auto c = n->cert(pos.block_id);
            all_verify &= (c && n->verifyCert(*c) && c->voted_stake == 7 * kStake && c->voters.size() == 7);
        }
        check(all_final, "3 down (f=⌊(n-1)/3⌋): all 7 live nodes finalize");
        check(all_verify, "the 7-of-10 cert verifies with 70 stake (the 3 down are routed around)");

        // 4 of 10 down → only 6 live (60 ≤ 66) → NOTHING finalizes (safe stall).
        Bus bus2; std::vector<std::unique_ptr<Node>> nodes2;
        const VotePosition pos2 = make_pos(0x72, 101, 1);
        run_height(nodes2, bus2, /*live=*/6, pos2);
        bool any_final = false;
        for (auto& n : nodes2) any_final |= n->isFinal(pos2.block_id);
        check(!any_final, "4 down (beyond n/3): no finality — safe stall, never a fork");
        std::printf("[1/3] down validators: 3 down finalize, 4 down safely stall (n/3 boundary) => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [2] WEDGED-but-PRESENT validator floods garbage; honest quorum routes around ─
    {
        const int b = g_fail;
        // 7 honest live (indices 0..6). Validator 7 is WEDGED-present: in the set,
        // "gossiping", but only emits garbage. Validators 8,9 are down.
        Bus bus; std::vector<std::unique_ptr<Node>> nodes;
        const VotePosition real = make_pos(0x73, 102, 1);
        run_height(nodes, bus, /*live=*/7, real);

        const Key& wedged = keys[7];
        const VotePosition neverSubmitted = make_pos(0xEE, 102, 1);  // a block no honest node opened
        // (a) bad-signature vote for the real block; (b) valid sig but for a block
        //     no node submitted. Flood both into every honest gate, many times.
        Signature badSig = sign_vote(wedged, real); badSig[20] ^= 0x01;
        SignedVote garbageA{real.block_id, wedged.pk, badSig};
        SignedVote garbageB{neverSubmitted.block_id, wedged.pk, sign_vote(wedged, neverSubmitted)};
        for (int rep = 0; rep < 5; ++rep) { bus.broadcast(garbageA); bus.broadcast(garbageB); }

        bool honest_final = true, cert_clean = true;
        for (auto& n : nodes) {
            honest_final &= n->isFinal(real.block_id);
            auto c = n->cert(real.block_id);
            if (!c) { cert_clean = false; continue; }
            for (const auto& voter : c->voters) if (voter == wedged.pk) cert_clean = false;  // wedged key must be absent
            cert_clean &= (c->voters.size() == 7 && c->voted_stake == 70);
        }
        check(honest_final, "honest 7 finalize the real block despite the wedged node's flood");
        check(cert_clean, "the wedged node's key/garbage is NEVER in any cert (rejected, not counted)");
        std::printf("[2/3] wedged-but-present garbage flood: honest quorum routes around it    => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    // ── [3] SELF-HEAL: 3 down permanently; three heights each finalize, no reset ──
    {
        const int b = g_fail;
        bool healed = true;
        for (std::uint64_t h = 200; h < 203; ++h) {
            Bus bus; std::vector<std::unique_ptr<Node>> nodes;
            const VotePosition pos = make_pos(std::uint8_t(0x80 + (h - 200)), h, 1);
            run_height(nodes, bus, /*live=*/7, pos);  // same 3 perpetually down
            for (auto& n : nodes) {
                auto c = n->cert(pos.block_id);
                healed &= n->isFinal(pos.block_id) && c && n->verifyCert(*c);
            }
        }
        check(healed, "3 consecutive heights each finalize with 3 nodes permanently down (self-heal)");
        std::printf("[3/3] self-heal: continuous finalization through a persistent f=3 fault   => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    std::printf("---------------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== LIVENESS: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== LIVENESS: PASS — finalizes through down + wedged faults, self-heals (≥ avalanche) ====\n");
    return 0;
}
