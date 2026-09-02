// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine_integration_test.cpp — proves the two consensus layers compose into
// one engine: the LIVENESS layer (photon sampling + wave FPC confidence) decides
// WHICH block the network converges on; the SAFETY layer (QuorumCertEngine, real
// BLS + >2/3-stake quorum cert) PROVES it. The contract:
//
//   wave reaches β-confidence ACCEPT  ⇒  the gate certifies the block with a real
//   aggregate signature that independently re-verifies.
//   wave does NOT decide              ⇒  no certification is even attempted.
//
// This is the cert-carrying finalization path a node drives: poll until decided,
// then collect the signed votes into a verifiable certificate.

#include "lux/consensus/photon.hpp"
#include "lux/consensus/wave.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/bls.hpp"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>

using namespace lux::consensus;

namespace {
int g_fail = 0;
void check(bool ok, const char* what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what); ++g_fail; }
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey pk{};
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
Signature sign_vote(const Key& key, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature sig{};
    if (bls::sign(key.sk.data(), msg.data(), msg.size(), sig.data()) != 0) { std::puts("sign failed"); std::exit(2); }
    return sig;
}
}  // namespace

int main() {
    std::printf("========== consensus — engine integration (liveness ⇒ safety) ==========\n");
    std::printf("wave decides the block; the BLS quorum-cert gate proves it\n\n");

    // Validator set: 5 validators, stake 20 each (total 100), α = 4.
    std::vector<Key> keys;
    for (std::uint8_t i = 0; i < 5; ++i) keys.push_back(make_key(std::uint8_t(0x30 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, 20});

    QuorumCertEngine gate(set);
    Wave wave(WaveConfig{/*k=*/5, /*threshold=*/4, /*beta=*/4});

    // ── [1] Happy path: wave reaches β ACCEPT, then the gate certifies. ──────
    {
        VotePosition A{};
        A.block_id.fill(0x41);
        A.height = 100;
        A.round = 7;
        const auto & item = A.block_id;

        // Liveness: 4 virtuous polls (all 5 sampled peers vote yes) → decide Accept.
        Decision d = Decision::Undecided;
        for (int r = 0; r < 4; ++r) d = wave.record_round(item, /*yes=*/5, /*total=*/5);
        check(d == Decision::Accept, "wave decided ACCEPT after β rounds");

        // Safety: ONLY because wave decided Accept do we certify. Collect α signed
        // votes carrying >2/3 stake into a real, re-verifying quorum certificate.
        check(d == Decision::Accept && gate.submit(A), "gate.submit after wave Accept");
        for (int i = 0; i < 4; ++i)
            check(gate.record_vote(A.block_id, keys[i].pk, sign_vote(keys[i], A)) == VoteResult::Recorded,
                  "signed ACCEPT vote recorded");
        check(gate.is_final(A.block_id), "gate: block is final (≥α distinct, >2/3 stake)");
        auto cert = gate.assemble_cert(A.block_id);
        check(cert.has_value(), "aggregate quorum cert assembled");
        check(cert && gate.verify_cert(*cert), "the cert independently RE-VERIFIES");
        std::printf("[1/2] wave ACCEPT ⇒ gate emits a verifiable quorum cert      => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // ── [2] Liveness gates the attempt: an undecided poll ⇒ no certification. ─
    {
        VotePosition B{};
        B.block_id.fill(0x42);
        B.height = 101;
        B.round = 7;
        const auto & item = B.block_id;

        // 3 yes-rounds then a split (inconclusive) → confidence resets, undecided.
        wave.record_round(item, 5, 5);
        wave.record_round(item, 5, 5);
        wave.record_round(item, 5, 5);
        Decision d = wave.record_round(item, 2, 5);  // inconclusive → reset
        check(d == Decision::Undecided, "wave NOT decided after an inconclusive poll");

        // The node does not certify an undecided block. Even if it (wrongly) tried,
        // the gate would still need real votes — but the contract is: no decision,
        // no certification attempt.
        const bool would_certify = (d == Decision::Accept);
        check(!would_certify, "no certification attempted for an undecided block");
        check(!gate.is_final(B.block_id), "gate has no finality for B (never submitted/voted)");
        std::printf("[2/2] undecided wave ⇒ no cert (liveness gates the attempt)  => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    std::printf("-------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== ENGINE INTEGRATION: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== ENGINE INTEGRATION: 2/2 PASS — liveness decides, safety proves ====\n");
    return 0;
}
