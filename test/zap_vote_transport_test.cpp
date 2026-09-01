// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// zap_vote_transport_test.cpp — proves consensus votes cross a REAL byte channel
// via the canonical ZAP wire codec, and that validators on opposite ends of a
// socket independently reach finality from wire-delivered votes. This closes the
// gap from "in-process bus" to "over the wire": the same VoteTransport seam, now
// backed by lux::zap framing over an OS socket.

#include "lux/consensus/node.hpp"
#include "lux/consensus/zap/vote_codec.hpp"
#include "lux/consensus/zap/zap_vote_transport.hpp"
#include "lux/consensus/bls.hpp"

#include <sys/socket.h>

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
VotePosition make_pos(std::uint8_t tag, std::uint64_t height, std::uint32_t round = 0) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.height = height;
    p.round  = round;
    return p;
}
}  // namespace

int main() {
    std::printf("============ consensus — votes over the ZAP wire (real socket) ============\n");
    std::printf("two validator groups exchange ZAP-framed votes and both finalize\n\n");

    // ── [1] ZAP codec round-trips a signed vote ──────────────────────────────
    {
        SignedVote v;
        v.block_id.fill(0xC1);
        v.voter.fill(0xB2);
        v.sig.fill(0x33);
        const auto frame = zap::encode_vote(v);
        const auto back = zap::decode_vote(frame);
        check(back.has_value(), "vote decodes from its ZAP frame");
        check(back && back->block_id == v.block_id && back->voter == v.voter && back->sig == v.sig,
              "round-trip is byte-identical");
        std::vector<std::uint8_t> truncated(frame.begin(), frame.begin() + frame.size() / 2);
        check(!zap::decode_vote(truncated).has_value(), "a truncated frame is rejected");
        std::printf("[1/2] ZAP codec round-trips a signed vote (truncation caught) => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // ── [2] over a real socketpair: group A (val 0-2) and group B (val 3-4)
    //        gossip ZAP-framed votes; both sides independently finalize. ───────
    {
        std::vector<Key> keys;
        for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x80 + i)));
        std::vector<Validator> set;
        for (const auto & k : keys) set.push_back({k.pk, 20});  // total 100, α=4, floor 66

        int fd[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) { std::puts("socketpair failed"); return 2; }

        // Two transports — one per end of the wire — each hosting its side's nodes.
        zap::ZapVoteTransport txA(fd[0]);
        zap::ZapVoteTransport txB(fd[1]);

        std::vector<std::unique_ptr<Party>> A, B;
        for (std::uint32_t i = 0; i < 3; ++i)  // group A: validators 0,1,2
            A.push_back(std::make_unique<Party>(i, keys[i].sk, keys[i].pk, set, 4, WaveConfig{5, 4, 4}, txA));
        for (std::uint32_t i = 3; i < 5; ++i)  // group B: validators 3,4
            B.push_back(std::make_unique<Party>(i, keys[i].sk, keys[i].pk, set, 4, WaveConfig{5, 4, 4}, txB));
        for (auto & n : A) txA.add_local(n.get());
        for (auto & n : B) txB.add_local(n.get());

        const VotePosition pos = make_pos(0x41, 1);
        for (auto & n : A) n->submit(pos);
        for (auto & n : B) n->submit(pos);

        // A votes (3 ZAP frames written to the wire); B reads them off the wire.
        // β=4 confirmation rounds — a node signs only on the β-confirmed wave
        // decision (not a single round), so drive the full confidence build.
        for (int r = 0; r < 4; ++r) for (auto & n : A) n->poll(pos.block_id, /*yes=*/5, /*total=*/5);
        for (int i = 0; i < 3; ++i) check(txB.pump(), "B reads an A vote off the ZAP wire");

        // B votes (2 frames); A reads them off the wire.
        for (int r = 0; r < 4; ++r) for (auto & n : B) n->poll(pos.block_id, 5, 5);
        for (int i = 0; i < 2; ++i) check(txA.pump(), "A reads a B vote off the ZAP wire");

        // Each side now holds all 5 votes — independently final, cert verifies.
        check(A[0]->isFinal(pos.block_id), "group A finalizes from wire-delivered votes");
        check(B[0]->isFinal(pos.block_id), "group B finalizes from wire-delivered votes");
        auto ca = A[0]->cert(pos.block_id);
        auto cb = B[0]->cert(pos.block_id);
        check(ca && A[0]->verifyCert(*ca) && ca->voted_stake == 100, "A's cert verifies with full 100 stake");
        check(cb && B[0]->verifyCert(*cb) && cb->voted_stake == 100, "B's cert verifies with full 100 stake");

        ::close(fd[0]);
        ::close(fd[1]);
        std::printf("[2/2] validators converge across a real ZAP socket           => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    std::printf("---------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== ZAP TRANSPORT: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== ZAP TRANSPORT: 2/2 PASS — consensus votes finalize over the ZAP wire ====\n");
    return 0;
}
