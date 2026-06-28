// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// batch_verify_attack_test.cpp — adversarial re-review of the O(1) batch-verify
// gate change. The change accepts votes pre-quorum WITHOUT a per-vote pairing and
// verifies ONE aggregate at quorum. This test tries to manufacture FALSE FINALITY
// against that design, with real BLS12-381 keys (so a vulnerability would actually
// reproduce). The safety invariant under test: is_final ⟹ every counted voter
// validly signed (block,height,epoch). The attacker holds in-set, POP'd keys.

#include "lux/consensus2/quorum_cert_engine.hpp"
#include "bls_signature.hpp"

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
    if (!ok) { std::printf("    EXPLOIT/FAIL: %s\n", what.c_str()); ++g_fail; }
}
struct Key { std::array<std::uint8_t, 32> sk{}; PubKey pk{}; };
Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{}; seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk2pk"); std::exit(2); }
    return k;
}
BlockId blk(std::uint8_t t) { BlockId b{}; b.fill(t); return b; }
Signature sign(const Key& k, const VotePosition& p) {
    auto m = canonical_vote_message(p); Signature s{};
    if (cevm::crypto::bls::sign(k.sk.data(), m.data(), m.size(), s.data()) != 0) { std::puts("sign"); std::exit(2); }
    return s;
}
}  // namespace

int main() {
    std::printf("====== batch-verify adversarial re-review (real BLS) ======\n\n");
    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x90 + i)));
    std::vector<Validator> set;
    for (auto& k : keys) set.push_back({k.pk, 20});  // total 100, α=4, floor 66

    // A1 — wrong-MESSAGE sig from an in-set validator padding a quorum: a valid sig
    //      by k3, but over a DIFFERENT position. Must be caught at quorum, evicted.
    {
        QuorumCertEngine e(set, 4);
        const VotePosition P{blk(0x41), 100, 7};
        const VotePosition OTHER{blk(0x42), 100, 7};  // different block id, same height/epoch
        e.submit(P);
        for (int i = 0; i < 3; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign(keys[i], P));
        // k3 signs OTHER (a genuine sig, but wrong position) and offers it for P.
        (void)e.record_vote(P.block_id, keys[3].pk, sign(keys[3], OTHER));
        check(!e.is_final(P.block_id), "A1: valid-but-wrong-position sig does NOT finalize");
        check(e.voted_stake(P.block_id) == 60, "A1: wrong-position vote evicted, stake refunded to 60");
    }

    // A2 — aggregate CANCELLATION attempt: two Byzantine in-set validators (k2,k3)
    //      try to pass the aggregate without both genuinely signing. We hold their
    //      secret keys, so if the design were vulnerable we could craft it. Try the
    //      negation/compensation: k2 submits a forged sig, k3 the "fix-up". The only
    //      aggregate that verifies is the genuine sum — so this must NOT finalize.
    {
        QuorumCertEngine e(set, 4);
        const VotePosition P{blk(0x43), 101, 7};
        e.submit(P);
        (void)e.record_vote(P.block_id, keys[0].pk, sign(keys[0], P));  // genuine
        (void)e.record_vote(P.block_id, keys[1].pk, sign(keys[1], P));  // genuine
        // k2 forged, k3 forged (each a corrupted genuine sig) — sum is not the genuine aggregate.
        Signature f2 = sign(keys[2], P); f2[30] ^= 0x01;
        Signature f3 = sign(keys[3], P); f3[60] ^= 0x01;
        (void)e.record_vote(P.block_id, keys[2].pk, f2);
        (void)e.record_vote(P.block_id, keys[3].pk, f3);
        check(!e.is_final(P.block_id), "A2: two forged sigs cannot pass the aggregate (no false finality)");
        check(e.voted_stake(P.block_id) == 40, "A2: both forged evicted, only the 2 genuine (40) remain");
        check(!e.assemble_cert(P.block_id).has_value(), "A2: no cert for a sub-quorum after eviction");
    }

    // A3 — identity/zero signature from an in-set validator.
    {
        QuorumCertEngine e(set, 4);
        const VotePosition P{blk(0x44), 102, 7};
        e.submit(P);
        for (int i = 0; i < 3; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign(keys[i], P));
        Signature zero{};  // all-zero "signature"
        (void)e.record_vote(P.block_id, keys[3].pk, zero);
        check(!e.is_final(P.block_id), "A3: zero/identity sig does NOT finalize");
    }

    // A4 — genuine quorum among forged padding: 4 genuine + 1 forged (k4). The 4
    //      genuine must finalize; the forged must NOT be in the cert.
    {
        QuorumCertEngine e(set, 4);
        const VotePosition P{blk(0x45), 103, 7};
        e.submit(P);
        for (int i = 0; i < 4; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign(keys[i], P));
        check(e.is_final(P.block_id), "A4: 4 genuine votes finalize");
        Signature f4 = sign(keys[4], P); f4[10] ^= 0x01;
        check(e.record_vote(P.block_id, keys[4].pk, f4) == VoteResult::RejectedBadSignature,
              "A4: post-quorum forged vote individually rejected");
        auto c = e.assemble_cert(P.block_id);
        check(c.has_value() && e.verify_cert(*c) && c->voters.size() == 4 && c->voted_stake == 80,
              "A4: cert carries exactly the 4 genuine voters (80 stake), verifies");
    }

    // A5 — stake-refund exactness after MULTIPLE evictions in one quorum check.
    {
        QuorumCertEngine e(set, 4);
        const VotePosition P{blk(0x46), 104, 7};
        e.submit(P);
        (void)e.record_vote(P.block_id, keys[0].pk, sign(keys[0], P));   // genuine
        Signature f1 = sign(keys[1], P); f1[5] ^= 0x01;                  // forged
        Signature f2 = sign(keys[2], P); f2[7] ^= 0x01;                  // forged
        (void)e.record_vote(P.block_id, keys[1].pk, f1);
        (void)e.record_vote(P.block_id, keys[2].pk, f2);
        (void)e.record_vote(P.block_id, keys[3].pk, sign(keys[3], P));   // genuine — triggers quorum (count 4)
        check(!e.is_final(P.block_id), "A5: 2 genuine + 2 forged does NOT finalize");
        check(e.voted_stake(P.block_id) == 40, "A5: both forged evicted — stake exactly 40 (no double-refund/desync)");
        check(e.distinct_voters(P.block_id) == 2, "A5: exactly the 2 genuine voters remain");
    }

    std::printf("\n----------------------------------------------------------\n");
    if (g_fail) { std::printf("==== BATCH-VERIFY ATTACK: %d EXPLOIT(S)/FAILURE(S) ====\n", g_fail); return 1; }
    std::printf("==== BATCH-VERIFY ATTACK: ALL HELD — no false finality manufactured ====\n");
    return 0;
}
