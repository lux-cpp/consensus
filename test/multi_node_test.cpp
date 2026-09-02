// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// multi_node_test.cpp — proves consensus is a genuine DISTRIBUTED protocol, not
// a single vote-counter: N independent Party instances, each with its own BLS key,
// each running the engine over the shared validator set, exchange signed votes
// through a VoteTransport and INDEPENDENTLY converge on the same quorum
// certificate. Includes a Byzantine validator and a sub-supermajority case.

#include "lux/consensus/node.hpp"
#include "lux/consensus/bls.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace lux::consensus;

namespace {
int g_fail = 0;
void check(bool ok, const std::string & what) {
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

// In-process vote bus — the VoteTransport a real ZAP gossip layer replaces. It
// fans every broadcast out to a set of subscriber nodes (delivery to honest nodes
// only; a partitioned/Byzantine node simply is not subscribed for that vote).
struct Bus : VoteTransport {
    std::vector<Party *> subs;
    void broadcast(const SignedVote & v) override {
        for (Party * n : subs) n->onVote(v);
    }
};

VotePosition make_pos(std::uint8_t tag, std::uint64_t height, std::uint32_t round = 0) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.height = height;
    p.round  = round;
    return p;
}
}  // namespace

int main() {
    std::printf("=============== consensus — multi-node distributed finality ===============\n");
    std::printf("5 independent validator nodes exchange signed votes and converge on one cert\n\n");

    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x70 + i)));
    std::vector<Validator> set;
    for (const auto & k : keys) set.push_back({k.pk, 20});  // total 100, α=4, floor=66

    auto make_nodes = [&](Bus & bus, std::vector<std::unique_ptr<Party>> & nodes) {
        for (std::uint32_t i = 0; i < 5; ++i)
            nodes.push_back(std::make_unique<Party>(i, keys[i].sk, keys[i].pk, set,
                                                   WaveConfig{5, 4, 4}, bus));
        for (auto & n : nodes) bus.subs.push_back(n.get());
    };

    // ── [1] all 5 honest: every node independently finalizes the same cert ───
    {
        Bus bus;
        std::vector<std::unique_ptr<Party>> nodes;
        make_nodes(bus, nodes);
        const VotePosition pos = make_pos(0x41, 1);
        for (auto & n : nodes) n->submit(pos);
        // β rounds; each node sees a 5/5 sample, votes once, broadcasts to all.
        for (int r = 0; r < 4; ++r)
            for (auto & n : nodes) n->poll(pos.block_id, /*yes=*/5, /*total=*/5);

        bool all_final = true, all_verify = true;
        std::optional<QuorumCert> first = nodes[0]->cert(pos.block_id);
        for (auto & n : nodes) {
            all_final &= n->isFinal(pos.block_id);
            auto c = n->cert(pos.block_id);
            all_verify &= (c.has_value() && n->verifyCert(*c));
        }
        check(all_final, "every node independently reached finality");
        check(all_verify, "every node's quorum cert verifies");
        check(first.has_value() && first->voters.size() == 5, "cert carries all 5 voters");
        check(first.has_value() && first->voted_stake == 100, "cert carries full 100 stake");
        std::printf("[1/3] 5 honest nodes converge on one verifiable cert        => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // ── [2] one Byzantine validator (votes for a DIFFERENT block) — honest
    //        nodes still finalize the real block on 4 honest votes (80 > 66). ──
    {
        Bus bus;
        std::vector<std::unique_ptr<Party>> nodes;
        make_nodes(bus, nodes);
        const VotePosition real = make_pos(0x42, 2);
        const VotePosition forged = make_pos(0x99, 2);  // same height, different block
        for (auto & n : nodes) { n->submit(real); n->submit(forged); }

        // Honest nodes 0..3 vote for `real`; Byzantine node 4 votes only for `forged`.
        for (int r = 0; r < 4; ++r) {
            for (int i = 0; i < 4; ++i) nodes[i]->poll(real.block_id, 5, 5);
            nodes[4]->poll(forged.block_id, 5, 5);   // equivocating / wrong-block vote
        }
        bool honest_final = true;
        for (int i = 0; i < 4; ++i) honest_final &= nodes[i]->isFinal(real.block_id);
        check(honest_final, "honest nodes finalize the real block (4 votes, 80 stake)");
        check(!nodes[0]->isFinal(forged.block_id), "the Byzantine forged block does NOT finalize");
        auto c = nodes[0]->cert(real.block_id);
        check(c.has_value() && c->voted_stake == 80, "real cert carries exactly the 4 honest votes (80 stake)");
        std::printf("[2/3] Byzantine wrong-block vote can't break honest finality => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // ── [3] only 3 honest votes (60 ≤ 66) ⇒ no finality (safety) ─────────────
    {
        Bus bus;
        std::vector<std::unique_ptr<Party>> nodes;
        make_nodes(bus, nodes);
        const VotePosition pos = make_pos(0x43, 3);
        for (auto & n : nodes) n->submit(pos);
        for (int r = 0; r < 4; ++r)
            for (int i = 0; i < 3; ++i) nodes[i]->poll(pos.block_id, 5, 5);  // only 3 vote
        bool any_final = false;
        for (auto & n : nodes) any_final |= n->isFinal(pos.block_id);
        check(!any_final, "no node finalizes with only 60/100 stake (≤ 2/3 floor)");
        std::printf("[3/3] sub-supermajority does not finalize on any node        => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    std::printf("---------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== MULTI-NODE: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== MULTI-NODE: 3/3 PASS — independent nodes converge, Byzantine-tolerant ====\n");
    return 0;
}
