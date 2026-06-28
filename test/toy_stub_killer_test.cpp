// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// toy_stub_killer_test.cpp — the acceptance gate for the consensus2 seed.
//
// Proves, with REAL BLS12-381 keys and signatures (cevm::crypto::bls, blst-
// backed), that QuorumCertEngine does what the toy stub (pkg/c) CANNOT:
//
//   1. a >2/3-stake quorum of α distinct signed votes FINALIZES, and the
//      assembled aggregate cert independently re-verifies;
//   2. one validator's vote REPLAYED 5× does NOT finalize (dedup defeats the
//      replay — the exact bug pkg/c gets wrong);
//   3. fewer than α distinct votes do NOT finalize;
//   4. a count-quorum WITHOUT a 2/3 stake supermajority does NOT finalize
//      (the stake gate is independent of the count gate);
//   5. forged / wrong-position BLS signatures are REJECTED, not counted.
//
// Exits non-zero on ANY failed assertion.

#include "lux/consensus2/quorum_cert_engine.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace lux::consensus2;

namespace {

int g_checks_passed = 0;
int g_checks_failed = 0;

// One leaf assertion. Records pass/fail; prints only failures (keeps a green run
// quiet and a red run loud).
bool check(bool cond, const std::string& what) {
    if (cond) {
        ++g_checks_passed;
    } else {
        ++g_checks_failed;
        std::printf("        FAIL: %s\n", what.c_str());
    }
    return cond;
}

// A real BLS keypair, deterministic from a one-byte tag (reproducible test).
struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey                       pk{};
};

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen failed"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk failed"); std::exit(2); }
    return k;
}

BlockId make_block(std::uint8_t tag) {
    BlockId b{};
    b.fill(tag);
    return b;
}

// Produce a real ACCEPT signature by `key` over the canonical message of `pos`.
Signature sign_vote(const Key& key, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature sig{};
    if (cevm::crypto::bls::sign(key.sk.data(), msg.data(), msg.size(), sig.data()) != 0) {
        std::puts("sign failed"); std::exit(2);
    }
    return sig;
}

void banner(int n, const char* title) {
    std::printf("[%d/5] %s\n", n, title);
}

void verdict(int n, bool ok) {
    std::printf("      => %s\n", ok ? "PASS" : "FAIL");
    (void)n;
}

}  // namespace

int main() {
    std::puts("================ consensus2 seed — TOY-STUB-KILLER ================");
    std::puts("real BLS12-381 (cevm::crypto::bls, blst) | finality GATE only\n");

    // ── Common fixture: 5 validators, stake 20 each (total 100), α = 4.
    //    floor(2/3·100) = 66 ⇒ a quorum needs >66 stake AND ≥4 distinct voters.
    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x10 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, 20});
    QuorumCertEngine engine(set, /*alpha=*/4);
    check(engine.total_stake() == 100, "fixture total stake == 100");
    check(two_thirds_stake_floor(100) == 66, "floor(2/3*100) == 66 (matches Go)");

    // ── [1/5] supermajority finalizes ───────────────────────────────────────
    banner(1, "α distinct votes with >2/3 stake FINALIZE");
    bool s1 = true;
    {
        const VotePosition A{make_block(0x41), /*height=*/100, /*epoch=*/7};
        s1 &= check(engine.submit(A), "submit(A)");
        for (int i = 0; i < 4; ++i)  // validators 0..3 → 4 distinct, 80 stake
            s1 &= check(engine.record_vote(A.block_id, keys[i].pk, sign_vote(keys[i], A)) == VoteResult::Accepted,
                        "validator " + std::to_string(i) + " ACCEPT recorded");
        s1 &= check(engine.distinct_voters(A.block_id) == 4, "4 distinct voters");
        s1 &= check(engine.voted_stake(A.block_id) == 80, "summed stake == 80 (>66)");
        s1 &= check(engine.is_final(A.block_id) == true, "is_final(A) == true");
    }
    verdict(1, s1);

    // ── [2/5] the assembled aggregate cert independently re-verifies ─────────
    banner(2, "the aggregate quorum cert RE-VERIFIES (and tamper is caught)");
    bool s2 = true;
    {
        const VotePosition A{make_block(0x42), /*height=*/100, /*epoch=*/7};
        s2 &= check(engine.submit(A), "submit(A2)");
        for (int i = 0; i < 4; ++i)
            (void)engine.record_vote(A.block_id, keys[i].pk, sign_vote(keys[i], A));
        auto cert = engine.assemble_cert(A.block_id);
        s2 &= check(cert.has_value(), "assemble_cert returns a cert for a final block");
        if (cert) {
            s2 &= check(cert->voters.size() == 4, "cert carries 4 distinct voters");
            s2 &= check(cert->version == kQuorumCertVersion && cert->type == kQCFinality,
                        "cert version/type bound");
            s2 &= check(engine.verify_cert(*cert) == true, "verify_cert(cert) == true (aggregate BLS holds)");
            QuorumCert tampered = *cert;        // flip one aggregate-sig byte
            tampered.aggregate_sig[10] ^= 0x01;
            s2 &= check(engine.verify_cert(tampered) == false, "tampered aggregate sig is REJECTED");
            QuorumCert dropped = *cert;         // drop a voter ⇒ aggregate no longer matches
            dropped.voters.pop_back();
            s2 &= check(engine.verify_cert(dropped) == false, "cert with a voter removed is REJECTED");
        }
    }
    verdict(2, s2);

    // ── [3/5] replay of a single vote 5× does NOT finalize ───────────────────
    banner(3, "ONE validator's vote replayed 5× does NOT finalize (dedup)");
    bool s3 = true;
    {
        const VotePosition B{make_block(0x43), /*height=*/101, /*epoch=*/7};
        s3 &= check(engine.submit(B), "submit(B)");
        const Signature v0 = sign_vote(keys[0], B);
        s3 &= check(engine.record_vote(B.block_id, keys[0].pk, v0) == VoteResult::Accepted,
                    "first vote Accepted");
        int dups = 0;
        for (int i = 0; i < 4; ++i)  // replay the SAME pubkey+sig 4 more times
            if (engine.record_vote(B.block_id, keys[0].pk, v0) == VoteResult::Duplicate) ++dups;
        s3 &= check(dups == 4, "4 replays each rejected as Duplicate");
        s3 &= check(engine.distinct_voters(B.block_id) == 1, "still only 1 distinct voter");
        s3 &= check(engine.voted_stake(B.block_id) == 20, "stake counted ONCE (==20)");
        s3 &= check(engine.is_final(B.block_id) == false, "is_final(B) == false");
        s3 &= check(engine.assemble_cert(B.block_id).has_value() == false, "no cert for a non-final block");
    }
    verdict(3, s3);

    // ── [4/5] sub-quorum (count OR stake short) does NOT finalize ────────────
    banner(4, "count-quorum WITHOUT 2/3 stake does NOT finalize");
    bool s4 = true;
    {
        // 4a: 3 distinct equal-stake voters — BOTH gates fail (3<4 and 60<=66).
        const VotePosition C{make_block(0x44), 102, 7};
        s4 &= check(engine.submit(C), "submit(C)");
        for (int i = 0; i < 3; ++i)
            (void)engine.record_vote(C.block_id, keys[i].pk, sign_vote(keys[i], C));
        s4 &= check(engine.distinct_voters(C.block_id) == 3, "3 distinct voters");
        s4 &= check(engine.is_final(C.block_id) == false, "is_final(C) == false (3<α and 60<=66)");

        // 4b: SKEWED stake — count gate PASSES but stake gate FAILS. Isolates the
        //     stake supermajority as an independent, required gate (the HIGH-3 fix).
        std::vector<Key> sk_keys;
        for (std::uint8_t i = 0; i < 5; ++i) sk_keys.push_back(make_key(std::uint8_t(0x60 + i)));
        std::vector<Validator> skewed = {
            {sk_keys[0].pk, 10}, {sk_keys[1].pk, 10}, {sk_keys[2].pk, 10},
            {sk_keys[3].pk, 10}, {sk_keys[4].pk, 60},  // total 100, floor 66
        };
        QuorumCertEngine skewed_engine(skewed, /*alpha=*/3);
        const VotePosition D{make_block(0x45), 103, 9};
        s4 &= check(skewed_engine.submit(D), "submit(D) on skewed engine");
        for (int i = 0; i < 3; ++i)  // the 3 low-stake validators: count 3>=α, stake 30
            (void)skewed_engine.record_vote(D.block_id, sk_keys[i].pk, sign_vote(sk_keys[i], D));
        s4 &= check(skewed_engine.distinct_voters(D.block_id) == 3, "skewed: 3 distinct voters (count gate PASSES)");
        s4 &= check(skewed_engine.voted_stake(D.block_id) == 30, "skewed: voted stake 30 (<=66)");
        s4 &= check(skewed_engine.is_final(D.block_id) == false,
                    "skewed: is_final == false despite reaching α (stake gate independent)");
        // and adding the whale flips it final (sanity: the gate is not stuck-closed)
        (void)skewed_engine.record_vote(D.block_id, sk_keys[4].pk, sign_vote(sk_keys[4], D));
        s4 &= check(skewed_engine.voted_stake(D.block_id) == 90, "skewed: +whale ⇒ stake 90 (>66)");
        s4 &= check(skewed_engine.is_final(D.block_id) == true, "skewed: now final with whale");
    }
    verdict(4, s4);

    // ── [5/5] forged sigs NEVER drive finality (O(1) batch-verify path) ──────
    //   Verification is deferred to ONE aggregate pairing at quorum (not α
    //   individual pairings). The toy-stub-killer property is unchanged in
    //   substance: a forged sig can pad the count/stake but is caught and evicted
    //   at the quorum check, so it can never finalize; only genuine sigs do.
    banner(5, "forged BLS sigs are evicted at quorum — never finalize");
    bool s5 = true;
    {
        const VotePosition E{make_block(0x46), 104, 7};
        s5 &= check(engine.submit(E), "submit(E)");

        // Out-of-set + unknown-block are cheap checks, still rejected per-vote.
        Key outsider = make_key(0xEE);
        s5 &= check(engine.record_vote(E.block_id, outsider.pk, sign_vote(outsider, E)) == VoteResult::RejectedUnknownValidator,
                    "out-of-set voter ⇒ RejectedUnknownValidator");
        s5 &= check(engine.record_vote(make_block(0x77), keys[0].pk, sign_vote(keys[0], E)) == VoteResult::RejectedNoSuchBlock,
                    "vote on unknown block ⇒ RejectedNoSuchBlock");

        // 3 GENUINE votes (k0,k1,k2) — below the α=4 quorum, so no verify yet.
        for (int i = 0; i < 3; ++i)
            s5 &= check(engine.record_vote(E.block_id, keys[i].pk, sign_vote(keys[i], E)) == VoteResult::Accepted,
                        "genuine candidate " + std::to_string(i) + " accepted");
        s5 &= check(!engine.is_final(E.block_id), "3 votes (60 stake) not final");

        // 4th vote is FORGED (k3): count→4 and stake→80 reach quorum, so the
        // aggregate verify runs, FAILS, and evicts the forged vote.
        Signature forged = sign_vote(keys[3], E);
        forged[20] ^= 0x01;
        s5 &= check(engine.record_vote(E.block_id, keys[3].pk, forged) == VoteResult::RejectedBadSignature,
                    "forged vote triggering the quorum check ⇒ RejectedBadSignature");
        s5 &= check(engine.distinct_voters(E.block_id) == 3, "forged vote evicted — 3 genuine remain");
        s5 &= check(engine.voted_stake(E.block_id) == 60, "stake refunded to 60 after eviction");
        s5 &= check(!engine.is_final(E.block_id), "a forged-padded quorum does NOT finalize");

        // k3's GENUINE sig now lands → real 4-of-5 / 80 stake → finalizes.
        s5 &= check(engine.record_vote(E.block_id, keys[3].pk, sign_vote(keys[3], E)) == VoteResult::Accepted,
                    "k3's valid sig accepted after its forged one was evicted");
        s5 &= check(engine.is_final(E.block_id), "genuine quorum finalizes");
        auto c5 = engine.assemble_cert(E.block_id);
        s5 &= check(c5.has_value() && engine.verify_cert(*c5) && c5->voted_stake == 80,
                    "cert verifies, carries only the 4 genuine voters (80 stake)");

        // post-quorum: a forged extra vote (k4) is individually rejected.
        Signature f4 = sign_vote(keys[4], E);
        f4[10] ^= 0x01;
        s5 &= check(engine.record_vote(E.block_id, keys[4].pk, f4) == VoteResult::RejectedBadSignature,
                    "post-quorum forged vote ⇒ RejectedBadSignature");
    }
    verdict(5, s5);

    // ── Summary ──────────────────────────────────────────────────────────────
    const bool all = (s1 && s2 && s3 && s4 && s5) && (g_checks_failed == 0);
    std::puts("\n------------------------------------------------------------------");
    std::printf("leaf checks: %d passed, %d failed\n", g_checks_passed, g_checks_failed);
    std::printf("scenarios:   [1]%s [2]%s [3]%s [4]%s [5]%s\n",
                s1 ? "PASS" : "FAIL", s2 ? "PASS" : "FAIL", s3 ? "PASS" : "FAIL",
                s4 ? "PASS" : "FAIL", s5 ? "PASS" : "FAIL");
    std::printf("==== TOY-STUB-KILLER: %s ====\n", all ? "5/5 PASS" : "FAILED");
    return all ? 0 : 1;
}
