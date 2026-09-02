// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// toy_stub_killer_test.cpp — the acceptance gate for the consensus seed.
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

#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/bls.hpp"

#include <blst.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace lux::consensus;

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
    if (bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen failed"); std::exit(2); }
    if (bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk failed"); std::exit(2); }
    return k;
}

BlockId make_block(std::uint8_t tag) {
    BlockId b{};
    b.fill(tag);
    return b;
}
VotePosition make_pos(std::uint8_t tag, std::uint64_t height, std::uint32_t round = 0) {
    VotePosition p{};
    p.block_id = make_block(tag);
    p.height   = height;
    p.round    = round;
    return p;
}

// Produce a real ACCEPT signature by `key` over the canonical message of `pos`.
Signature sign_vote(const Key& key, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature sig{};
    if (bls::sign(key.sk.data(), msg.data(), msg.size(), sig.data()) != 0) {
        std::puts("sign failed"); std::exit(2);
    }
    return sig;
}

void banner(int n, const char* title) {
    std::printf("[%d/6] %s\n", n, title);
}

void verdict(int n, bool ok) {
    std::printf("      => %s\n", ok ? "PASS" : "FAIL");
    (void)n;
}

}  // namespace

int main() {
    std::puts("================ consensus seed — TOY-STUB-KILLER ================");
    std::puts("real BLS12-381 (cevm::crypto::bls, blst) | finality GATE only\n");

    // ── Common fixture: 5 validators, stake 20 each (total 100). floor(2/3·100)
    //    = 66 and the export count floor is floor(2·5/3)+1 = 4, both DERIVED from
    //    the set ⇒ an export quorum needs >66 stake AND ≥4 distinct voters.
    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x10 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, 20});
    QuorumCertEngine engine(set);
    check(engine.total_stake() == 100, "fixture total stake == 100");
    check(two_thirds_stake_floor(100) == 66, "floor(2/3*100) == 66 (matches Go)");

    // ── [1/5] supermajority finalizes ───────────────────────────────────────
    banner(1, "α distinct votes with >2/3 stake FINALIZE");
    bool s1 = true;
    {
        const VotePosition A = make_pos(0x41, 100, 7);
        s1 &= check(engine.submit(A), "submit(A)");
        for (int i = 0; i < 4; ++i)  // validators 0..3 → 4 distinct, 80 stake
            s1 &= check(engine.record_vote(A.block_id, keys[i].pk, sign_vote(keys[i], A)) == VoteResult::Recorded,
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
        const VotePosition A = make_pos(0x42, 100, 7);
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
        const VotePosition B = make_pos(0x43, 101, 7);
        s3 &= check(engine.submit(B), "submit(B)");
        const Signature v0 = sign_vote(keys[0], B);
        s3 &= check(engine.record_vote(B.block_id, keys[0].pk, v0) == VoteResult::Recorded,
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
        const VotePosition C = make_pos(0x44, 102, 7);
        s4 &= check(engine.submit(C), "submit(C)");
        for (int i = 0; i < 3; ++i)
            (void)engine.record_vote(C.block_id, keys[i].pk, sign_vote(keys[i], C));
        s4 &= check(engine.distinct_voters(C.block_id) == 3, "3 distinct voters");
        s4 &= check(engine.is_final(C.block_id) == false,
                    "is_final(C) == false (3 < the floor of 4, and 60<=66)");

        // 4b: SKEWED stake — count gate PASSES but stake gate FAILS. Isolates the
        //     stake supermajority as an independent, required gate (the HIGH-3 fix).
        //     FOUR light voters, because four is what the export count floor asks
        //     of five seats; with three the count would fail too and the row would
        //     no longer isolate anything.
        std::vector<Key> sk_keys;
        for (std::uint8_t i = 0; i < 5; ++i) sk_keys.push_back(make_key(std::uint8_t(0x60 + i)));
        std::vector<Validator> skewed = {
            {sk_keys[0].pk, 10}, {sk_keys[1].pk, 10}, {sk_keys[2].pk, 10},
            {sk_keys[3].pk, 10}, {sk_keys[4].pk, 60},  // total 100, floor 66
        };
        QuorumCertEngine skewed_engine(skewed);
        s4 &= check(skewed_engine.signer_floor(Tier::Quasar) == 4,
                    "skewed: the export count floor for five seats is 4");
        const VotePosition D = make_pos(0x45, 103, 9);
        s4 &= check(skewed_engine.submit(D), "submit(D) on skewed engine");
        for (int i = 0; i < 4; ++i)  // the 4 low-stake validators: they meet the count and not the stake
            (void)skewed_engine.record_vote(D.block_id, sk_keys[i].pk, sign_vote(sk_keys[i], D));
        s4 &= check(skewed_engine.distinct_voters(D.block_id) == 4, "skewed: 4 distinct voters (count gate PASSES)");
        s4 &= check(skewed_engine.voted_stake(D.block_id) == 40, "skewed: voted stake 40 (<=66)");
        s4 &= check(skewed_engine.is_final(D.block_id) == false,
                    "skewed: is_final == false despite meeting the count (stake gate independent)");
        // and adding the whale flips it final (sanity: the gate is not stuck-closed)
        (void)skewed_engine.record_vote(D.block_id, sk_keys[4].pk, sign_vote(sk_keys[4], D));
        s4 &= check(skewed_engine.voted_stake(D.block_id) == 100, "skewed: +whale ⇒ stake 100 (>66)");
        s4 &= check(skewed_engine.is_final(D.block_id) == true, "skewed: now final with whale");
    }
    verdict(4, s4);

    // ── [5/5] forged sigs NEVER drive finality (O(1) batch-verify path) ──────
    //   Verification is ONE aggregate pairing at the GATE (not α individual
    //   pairings on the receive path). The toy-stub-killer property is unchanged in
    //   substance: a forged sig can pad the count/stake but is caught and evicted
    //   when finality is asked, so it can never finalize; only genuine sigs do.
    banner(5, "forged BLS sigs are evicted at the gate — never finalize");
    bool s5 = true;
    {
        const VotePosition E = make_pos(0x46, 104, 7);
        s5 &= check(engine.submit(E), "submit(E)");

        // Out-of-set + unknown-block are cheap checks, still rejected per-vote.
        Key outsider = make_key(0xEE);
        s5 &= check(engine.record_vote(E.block_id, outsider.pk, sign_vote(outsider, E)) == VoteResult::RejectedUnknownValidator,
                    "out-of-set voter ⇒ RejectedUnknownValidator");
        s5 &= check(engine.record_vote(make_block(0x77), keys[0].pk, sign_vote(keys[0], E)) == VoteResult::RejectedNoSuchBlock,
                    "vote on unknown block ⇒ RejectedNoSuchBlock");

        // 3 GENUINE votes (k0,k1,k2) — below the α=4 quorum, so no verify yet.
        for (int i = 0; i < 3; ++i)
            s5 &= check(engine.record_vote(E.block_id, keys[i].pk, sign_vote(keys[i], E)) == VoteResult::Recorded,
                        "genuine candidate " + std::to_string(i) + " accepted");
        s5 &= check(!engine.is_final(E.block_id), "3 votes (60 stake) not final");

        // 4th vote is FORGED (k3): count→4 and stake→80 clear the floors, so asking
        // the gate runs the aggregate verify, which FAILS and evicts the forged vote.
        Signature forged = sign_vote(keys[3], E);
        forged[20] ^= 0x01;
        s5 &= check(engine.record_vote(E.block_id, keys[3].pk, forged) == VoteResult::Recorded,
                    "the forged vote is RECORDED — a candidate is not a verified vote");
        s5 &= check(!engine.is_final(E.block_id), "a forged-padded quorum does NOT finalize");
        s5 &= check(engine.distinct_voters(E.block_id) == 3, "forged vote evicted — 3 genuine remain");
        s5 &= check(engine.voted_stake(E.block_id) == 60, "stake refunded to 60 after eviction");

        // k3's GENUINE sig now lands → real 4-of-5 / 80 stake → finalizes.
        s5 &= check(engine.record_vote(E.block_id, keys[3].pk, sign_vote(keys[3], E)) == VoteResult::Recorded,
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

    // ── [6] the crypto surface itself refuses what a stub would wave through ──
    // A stub verifies. That is the whole of what makes it a stub: it says yes,
    // and it says yes to anything, because it never decoded anything. So the
    // arguments no real implementation can accept are the sharpest thing to ask
    // it about — a null key, a secret key outside the scalar field, a public key
    // that is not a point, an aggregate over no keys at all.
    banner(6, "the BLS surface refuses malformed arguments rather than answering yes");
    bool s6 = true;
    {
        const Key k = make_key(0x51);
        const VotePosition P = make_pos(0xF1, 900);
        const std::vector<std::uint8_t> msg = canonical_vote_message(P);
        const Signature sig = sign_vote(k, P);

        s6 &= check(bls::verify(k.pk.data(), msg.data(), msg.size(), sig.data()) == 0,
                    "the genuine signature verifies — every refusal below is one edit from it");

        // Signing. A zero secret key is not a scalar; nor is one at or above the
        // group order. Both must fail the IRTF range check, not produce a
        // signature over a degenerate key.
        Signature out{};
        std::array<std::uint8_t, 32> zero_sk{};
        s6 &= check(bls::sign(nullptr, msg.data(), msg.size(), out.data()) != 0,
                    "signing with a null secret key fails");
        s6 &= check(bls::sign(k.sk.data(), msg.data(), msg.size(), nullptr) != 0,
                    "signing into a null buffer fails");
        s6 &= check(bls::sign(k.sk.data(), nullptr, 7, out.data()) != 0,
                    "signing a null message of non-zero length fails");
        s6 &= check(bls::sign(zero_sk.data(), msg.data(), msg.size(), out.data()) != 0,
                    "the zero secret key is refused — it is not a scalar");
        std::array<std::uint8_t, 32> huge_sk{};
        huge_sk.fill(0xFF);
        s6 &= check(bls::sign(huge_sk.data(), msg.data(), msg.size(), out.data()) != 0,
                    "and a secret key at or above the group order is refused too");
        s6 &= check(bls::sign(k.sk.data(), nullptr, 0, out.data()) == 0,
                    "a genuinely empty message signs — null with length zero IS empty");

        // Verifying. The two failure CLASSES are distinguished: -1 says the bytes
        // were never a point, 1 says they were a point and the pairing said no.
        // Collapsing them would tell a caller to retry what it should drop.
        PubKey garbage_pk{};
        garbage_pk.fill(0xAB);
        Signature garbage_sig{};
        garbage_sig.fill(0xCD);
        s6 &= check(bls::verify(nullptr, msg.data(), msg.size(), sig.data()) == -1,
                    "a null public key is a decode failure");
        s6 &= check(bls::verify(k.pk.data(), msg.data(), msg.size(), nullptr) == -1,
                    "and so is a null signature");
        s6 &= check(bls::verify(k.pk.data(), nullptr, 7, sig.data()) == -1,
                    "a null message of non-zero length is refused before any pairing");
        s6 &= check(bls::verify(garbage_pk.data(), msg.data(), msg.size(), sig.data()) == -1,
                    "a public key that is not a point is a decode failure, not a verdict");
        s6 &= check(bls::verify(k.pk.data(), msg.data(), msg.size(), garbage_sig.data()) == -1,
                    "a signature that is not a point likewise");
        Signature flipped = sig;
        flipped[95] ^= 0x01;
        s6 &= check(bls::verify(k.pk.data(), msg.data(), msg.size(), flipped.data()) != 0,
                    "a signature with one bit flipped does not verify");
        const std::vector<std::uint8_t> other = canonical_vote_message(make_pos(0xF2, 901));
        s6 &= check(bls::verify(k.pk.data(), other.data(), other.size(), sig.data()) == 1,
                    "a signature over another position decodes and then FAILS the pairing");

        // Aggregate verification over a set. Zero keys is not an aggregate, and a
        // key that will not decode cannot be summed into one.
        std::vector<std::uint8_t> pks(k.pk.begin(), k.pk.end());
        s6 &= check(bls::fast_aggregate_verify(pks.data(), 1, msg.data(), msg.size(), sig.data()) == 0,
                    "an aggregate over one key is that key's own verification");
        s6 &= check(bls::fast_aggregate_verify(nullptr, 1, msg.data(), msg.size(), sig.data()) != 0,
                    "a null key array is refused");
        s6 &= check(bls::fast_aggregate_verify(pks.data(), 1, msg.data(), msg.size(), nullptr) != 0,
                    "and a null aggregate signature");
        s6 &= check(bls::fast_aggregate_verify(pks.data(), 0, msg.data(), msg.size(), sig.data()) != 0,
                    "an aggregate over ZERO keys is refused — it would verify against nothing");
        s6 &= check(bls::fast_aggregate_verify(pks.data(), 1, nullptr, 7, sig.data()) != 0,
                    "a null message of non-zero length is refused here too");
        std::vector<std::uint8_t> bad_pks(48, 0xAB);
        s6 &= check(bls::fast_aggregate_verify(bad_pks.data(), 1, msg.data(), msg.size(), sig.data()) != 0,
                    "a key that will not decode cannot be aggregated");

        // An EMPTY message is a message. A null pointer with length zero is how C
        // spells one, and refusing it would refuse a signature that is perfectly
        // well formed — the guard is against a null pointer that claims LENGTH,
        // which is a caller bug, and not against emptiness.
        Signature over_empty{};
        if (bls::sign(k.sk.data(), nullptr, 0, over_empty.data()) != 0) { std::puts("sign empty"); std::exit(2); }
        s6 &= check(bls::verify(k.pk.data(), nullptr, 0, over_empty.data()) == 0,
                    "a signature over the empty message verifies");
        s6 &= check(bls::fast_aggregate_verify(pks.data(), 1, nullptr, 0, over_empty.data()) == 0,
                    "and aggregates the same way");
        s6 &= check(bls::verify(k.pk.data(), nullptr, 0, sig.data()) == 1,
                    "while a signature over a NON-empty message fails against the empty one");

        // key_validate is the one definition of what a key is, shared with the
        // gate's constructor and the possession door.
        s6 &= check(bls::key_validate(k.pk.data()), "a real key validates");
        s6 &= check(!bls::key_validate(nullptr), "a null key does not");
        s6 &= check(!bls::key_validate(garbage_pk.data()), "and neither does a non-point");
        PubKey identity{};
        identity[0] = 0xC0;
        s6 &= check(!bls::key_validate(identity.data()),
                    "the identity is refused — it would verify a signature over any message");

        // On the curve, outside the prime-order subgroup. It gets PAST the decode
        // clause, which is why the subgroup check is a separate one: without it a
        // point of small order can be made to pair to the identity (RFC 9380 §4.1).
        // The answer is 1, not -1: it decoded, so it is a failed verification and
        // not a malformed argument.
        PubKey off_g1{};
        {
            bool found = false;
            for (std::uint32_t x = 1; x < 4096 && !found; ++x) {
                off_g1.fill(0);
                off_g1[47] = std::uint8_t(x);
                off_g1[46] = std::uint8_t(x >> 8);
                off_g1[0] |= 0x80;
                blst_p1_affine a;
                found = blst_p1_uncompress(&a, off_g1.data()) == BLST_SUCCESS &&
                        !blst_p1_affine_in_g1(&a);
            }
            if (!found) { std::puts("no off-subgroup G1 candidate"); std::exit(2); }
        }
        s6 &= check(!bls::key_validate(off_g1.data()), "an off-subgroup point is not a key");
        s6 &= check(bls::verify(off_g1.data(), msg.data(), msg.size(), sig.data()) == 1,
                    "an off-subgroup public key decodes and then FAILS — never verifies");

        // The possession door shares the key leg with the gate, and adds its own
        // for the proof. Its three answers are distinct on purpose: Key and Proof
        // say which side never decoded, Possession says both decoded and the pair
        // is not bound.
        Signature off_g2{};
        {
            bool found = false;
            for (std::uint32_t x = 1; x < 4096 && !found; ++x) {
                off_g2.fill(0);
                off_g2[95] = std::uint8_t(x);
                off_g2[94] = std::uint8_t(x >> 8);
                off_g2[0] |= 0x80;
                blst_p2_affine a;
                found = blst_p2_uncompress(&a, off_g2.data()) == BLST_SUCCESS &&
                        !blst_p2_affine_in_g2(&a);
            }
            if (!found) { std::puts("no off-subgroup G2 candidate"); std::exit(2); }
        }
        std::array<std::uint8_t, bls::kNodeLen> node{};
        node.fill(0x11);
        Signature proof{};  // a proof this key never made
        s6 &= check(bls::pop_verify(nullptr, k.pk.data(), proof.data()) == bls::Pop::Key,
                    "a null node identity is a key-leg refusal");
        s6 &= check(bls::pop_verify(node.data(), k.pk.data(), nullptr) == bls::Pop::Key,
                    "and so is a null proof — there is nothing to decode on either side");
        s6 &= check(bls::pop_verify(node.data(), garbage_pk.data(), off_g2.data()) == bls::Pop::Key,
                    "a key that is not a point is refused on the KEY leg, before the proof");
        s6 &= check(bls::pop_verify(node.data(), k.pk.data(), off_g2.data()) == bls::Pop::Proof,
                    "an off-subgroup proof is refused on the PROOF leg, before any pairing");
        s6 &= check(bls::pop_verify(node.data(), k.pk.data(), sig.data()) == bls::Pop::Possession,
                    "and a well-formed proof that does not bind this pair is a POSSESSION refusal");
    }
    verdict(6, s6);

    // ── Summary ──────────────────────────────────────────────────────────────
    const bool all = (s1 && s2 && s3 && s4 && s5 && s6) && (g_checks_failed == 0);
    std::puts("\n------------------------------------------------------------------");
    std::printf("leaf checks: %d passed, %d failed\n", g_checks_passed, g_checks_failed);
    std::printf("scenarios:   [1]%s [2]%s [3]%s [4]%s [5]%s [6]%s\n",
                s1 ? "PASS" : "FAIL", s2 ? "PASS" : "FAIL", s3 ? "PASS" : "FAIL",
                s4 ? "PASS" : "FAIL", s5 ? "PASS" : "FAIL", s6 ? "PASS" : "FAIL");
    std::printf("==== TOY-STUB-KILLER: %s ====\n", all ? "6/6 PASS" : "FAILED");
    return all ? 0 : 1;
}
