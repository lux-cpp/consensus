// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// party_test.cpp — the admission door, wired to the thing that runs consensus.
//
// THIS FILE IS ITSELF THE FIRST HALF OF THE PROOF. It includes node.hpp and
// registration.hpp together, and until the participant was renamed to Party no
// translation unit could: node.hpp's participant and cert.hpp's twenty-byte
// identity were both `lux::consensus::Node`, so the two headers could not be
// held at once. The door speaks entirely in that identity, which meant the door
// could be tested and the mesh could be tested and NOTHING could test the join
// between them. That is the gap this file closes.
//
// THE JOIN IS THE POINT. A party signs with a KEY, and the engine counts keys. A
// certificate names a NODE, and the verifier resolves names. Those are two
// namings of one validator, and exactly one thing says which key answers to which
// name: the set the door admitted. So the path runs end to end —
//
//   registrations → admit() → CanonicalSet
//                             ├─ weights()  → the gate every party decides on
//                             └─ install()  → the registry every certificate is
//                                             checked against
//
// — and a certificate assembled from the votes the parties actually broadcast,
// attributed by that set, verifies against that registry. Both halves descend
// from one admission or the test fails.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/node.hpp"          // Party — the participant
#include "lux/consensus/registration.hpp"  // admit, CanonicalSet — and, through
                                           // cert.hpp, Node the identity
#include "lux/consensus/threshold.hpp"

#include <blst.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace lux::consensus;

// Two names, two things — the collision that kept them apart is gone, and this
// is the assertion that it stays gone.
static_assert(!std::is_same_v<Party, Node>,
              "the participant and the identity it is known by are two types");
static_assert(std::tuple_size_v<Node> == kNodeLen,
              "the identity a certificate names is the twenty bytes a proof binds");

namespace {

int g_pass = 0, g_fail = 0;
void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("    ok   %s\n", what.c_str()); return; }
    ++g_fail;
    std::printf("    FAIL %s\n", what.c_str());
}

[[noreturn]] void die(const char* what) {
    std::printf("party_test: %s\n", what);
    std::exit(2);
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey                       pk{};
};

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0x3C ^ (tag + i));
    Key k;
    if (bls::keygen(seed.data(), k.sk.data()) != 0) die("keygen");
    if (bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) die("sk_to_pk");
    return k;
}

Node make_node(std::uint8_t tag) {
    Node n{};
    n.fill(tag);
    return n;
}

// The proof a registrant makes for its own pair — a signature by sk over the
// 68-byte node ‖ key under the POP domain, checked here by the same verifier the
// door will use, so nothing below rests on this function being right.
std::vector<std::uint8_t> mint(const Key& k, const Node& node) {
    std::uint8_t msg[bls::kNodeLen + 48];
    std::memcpy(msg, node.data(), bls::kNodeLen);
    std::memcpy(msg + bls::kNodeLen, k.pk.data(), 48);

    blst_scalar s;
    blst_scalar_from_bendian(&s, k.sk.data());
    blst_p2 hash;
    blst_hash_to_g2(&hash, msg, sizeof(msg),
                    reinterpret_cast<const std::uint8_t*>(bls::kPopDST), bls::kPopDSTLen,
                    /*aug=*/nullptr, /*aug_len=*/0);
    blst_p2 sig;
    blst_sign_pk_in_g1(&sig, &hash, &s);

    std::vector<std::uint8_t> proof(96);
    blst_p2_compress(proof.data(), &sig);
    if (bls::pop_verify(node.data(), k.pk.data(), proof.data()) != bls::Pop::Ok)
        die("minted a proof the conformant verifier refuses");
    return proof;
}

Registration reg(const Key& k, const Node& node, std::uint64_t weight) {
    return Registration{node, {k.pk.begin(), k.pk.end()}, mint(k, node), weight};
}

// The in-process mesh, and a tap on it: every vote a party broadcasts is kept, so
// the certificate below is assembled from signatures the protocol really
// produced rather than ones the test minted for itself.
struct Bus : VoteTransport {
    std::vector<Party*>     subs;
    std::vector<SignedVote> heard;

    void broadcast(const SignedVote& v) override {
        heard.push_back(v);
        for (Party* p : subs) p->onVote(v);
    }
};

VotePosition make_pos(std::uint8_t tag, std::uint64_t height) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.canonical_id.fill(std::uint8_t(tag ^ 0xFF));
    p.height = height;
    p.round  = 1;
    return p;
}

// The one thing that says which key answers to which name.
std::optional<Node> name_of(const CanonicalSet& set, const PubKey& key) {
    for (const CanonicalValidator& v : set.validators)
        if (v.key == key) return v.node;
    return std::nullopt;
}

}  // namespace

int main() {
    std::printf("================================================================================\n");
    std::printf("PARTY — the admitted set is the set the participants run on\n");
    std::printf("================================================================================\n");

    constexpr std::size_t   kN     = 5;
    constexpr std::uint64_t kStake = 20;

    std::vector<Key>  keys;
    std::vector<Node> names;
    for (std::uint8_t i = 0; i < kN; ++i) {
        keys.push_back(make_key(std::uint8_t(0xB0 + i)));
        names.push_back(make_node(std::uint8_t(0x21 + i)));
    }

    // ── 1. The door ──────────────────────────────────────────────────────────
    std::printf("\n[1] five participants present a proof each, and the door admits them\n");
    std::vector<Registration> roster;
    for (std::size_t i = 0; i < kN; ++i) roster.push_back(reg(keys[i], names[i], kStake));

    CanonicalSet    set;
    const Admission ok = admit(roster, set);
    check(bool(ok), "the roster is admitted");
    check(set.validators.size() == kN && set.total_weight == kN * kStake,
          "…as five validators carrying the staked total");

    Registry registry;
    check(set.install(registry), "the admitted set seats the certificate registry");
    check(registry.size() == kN, "five distinct names, five distinct keys");

    // ── 2. The mesh ──────────────────────────────────────────────────────────
    // Every party decides over set.weights() and nothing else, so no party can
    // count a key the door did not prove.
    std::printf("\n[2] every party runs on that set, and the mesh finalizes\n");
    const WaveConfig      wave = WaveConfig::feasible(kN);
    Bus                   bus;
    std::vector<std::unique_ptr<Party>> parties;
    for (std::uint32_t i = 0; i < kN; ++i)
        parties.push_back(std::make_unique<Party>(i, keys[i].sk, keys[i].pk, set.weights(),
                                                  wave, bus));
    for (auto& p : parties) bus.subs.push_back(p.get());

    // Each party carries the roster slot it was built for. The mesh attributes a
    // vote by the KEY on it, so this is not what makes a vote countable — but a
    // party that reported someone else's slot would make every log line and every
    // "which one of you did that" question answer wrong.
    bool slots_own = true;
    for (std::uint32_t i = 0; i < kN; ++i) slots_own &= parties[i]->index() == i;
    check(slots_own, "each party reports the roster slot it was constructed for");

    const VotePosition pos = make_pos(0x5C, 9);
    for (auto& p : parties) p->submit(pos);
    for (std::uint32_t r = 0; r < wave.beta; ++r)
        for (auto& p : parties) p->poll(pos.block_id, wave.k, wave.k);

    bool all_final = true;
    for (auto& p : parties) all_final &= p->isFinal(pos.block_id, Tier::Quasar);
    check(all_final, "every party independently reaches Quasar finality");
    check(bus.heard.size() == kN, "…having broadcast exactly one ACCEPT vote each");

    bool every_voter_admitted = true;
    for (const SignedVote& v : bus.heard) every_voter_admitted &= name_of(set, v.voter).has_value();
    check(every_voter_admitted, "…and every voter on the wire is a key the door admitted");

    // ── 3. The join ──────────────────────────────────────────────────────────
    std::printf("\n[3] the certificate names the identities the door bound to those keys\n");
    Cert cert;
    cert.position  = pos;
    cert.threshold = kN;
    for (const SignedVote& v : bus.heard) {
        const std::optional<Node> who = name_of(set, v.voter);
        if (!who) die("a vote from a key that was never admitted");
        cert.votes.push_back(Vote{*who, true, {v.sig.begin(), v.sig.end()}});
    }
    std::sort(cert.votes.begin(), cert.votes.end(),
              [](const Vote& a, const Vote& b) { return a.node < b.node; });
    check(cert.verify(registry) == Refusal::None,
          "a certificate built from the mesh's own votes verifies against the seated registry");

    // ── 4. The join is load-bearing ──────────────────────────────────────────
    // If the names were interchangeable the test above would prove nothing: it
    // would pass on any assignment of signatures to identities.
    std::printf("\n[4] and the binding is not decoration\n");
    {
        Cert swapped = cert;
        std::swap(swapped.votes[0].signature, swapped.votes[1].signature);
        check(swapped.verify(registry) == Refusal::Signature,
              "two admitted parties' signatures traded between their names are refused");

        const Key  outsider      = make_key(0xC9);
        const Node outsider_name = make_node(0xF4);
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, true);
        Signature s{};
        if (bls::sign(outsider.sk.data(), msg.data(), msg.size(), s.data()) != 0) die("sign");
        Cert stranger;
        stranger.position  = pos;
        stranger.threshold = 1;
        stranger.votes     = {Vote{outsider_name, true, {s.begin(), s.end()}}};
        check(stranger.verify(registry) == Refusal::Signature,
              "a perfectly valid signature from a name the set never admitted is refused");
    }

    // ── 5. A hazardous roster never becomes a mesh ───────────────────────────
    // The whole reason the door is upstream: there is no admitted set to build a
    // gate or a registry from, so the mesh is not something that gets built and
    // then caught.
    std::printf("\n[5] a roster carrying the hazard produces no set to run on\n");
    {
        std::vector<Registration> hazardous = roster;
        hazardous.push_back(reg(keys[0], make_node(0xE7), kStake));  // keys[0] under a second name

        CanonicalSet    none;
        const Admission refused = admit(hazardous, none);
        check(refused.why == Admission::Why::DuplicateKey,
              "one holder under two names is refused at the door");
        check(none.validators.empty() && none.total_weight == 0,
              "…leaving no set to construct a gate or seat a registry from");

        // The refused set is the EMPTY set, which seats — Go admits an empty
        // registration batch too — and seats nobody. So the certificate the real
        // mesh produced finds no key to be checked against, which is what "no
        // set to run on" costs an attacker who got this far.
        Registry nobody;
        check(none.install(nobody) && nobody.size() == 0,
              "…the empty set it left behind seats no one");
        check(cert.verify(nobody) == Refusal::Signature,
              "…so even a genuine certificate resolves to nothing there");
    }

    std::printf("\n--------------------------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== PARTY: FAIL ====\n"); return 1; }
    std::printf("==== PARTY: PASS — one admission feeds the gate, the mesh and the registry ====\n");
    return 0;
}
