// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// registration_test.cpp — the admission door, against the rule Go writes in
// validator/registration.go.
//
// The properties under test are the ones a door can get wrong, and the first one
// is the reason the door exists at all:
//
//   0. THE HAZARD IS REAL. Two node ids resolving to ONE key clear a two-signer
//      floor on ONE holder's signature. That set is buildable by hand today —
//      Registry::insert takes whatever pairs it is given — and the certificate
//      verifier is right to accept it, because the set it was handed says two
//      nodes signed. Nothing downstream can catch this; only the door can.
//   1. POSSESSION IS REQUIRED. No proof, a wrong-width proof, a proof lifted from
//      another node, and the IETF pubkey-only proof are each refused.
//   2. ONE KEY, ONE NODE. Both registrations are individually SOUND — the holder
//      of a key can mint a genuine node-bound proof for any identity it likes —
//      so possession cannot refuse this, and uniqueness must.
//   3. ONE NODE, ONE KEY. The other axis, and neither implies the other.
//   4. ZERO WEIGHT IS REFUSED: a signer that counts toward the signer floor and
//      not toward the stake floor puts the two floors out of step.
//   5. THE SET IS WHOLE. One bad registration fails the call; a refused call
//      returns no partial set, because a set that lost a signer has a total
//      weight that no longer describes it.
//   6. THE VERDICT IS A FUNCTION OF THE SET, not of the caller's vector order.
//   7. THE ADMITTED SET IS THE ONE THE GATE RUNS ON: it constructs the engine and
//      seats the certificate registry, closing the loop the hazard opened.
//
// Every proof used here is minted under the PROOF domain and then handed to
// bls::pop_verify — the function pop_conformance_test pins byte-for-byte against
// the Go corpus — before it is used. A minting bug therefore cannot quietly turn
// a "both proofs are genuine" case into a weaker one.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/cert.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/registration.hpp"

#include "bls_signature.hpp"  // the eth2 ..._RO_POP_ surface: the pubkey-only proof

#include <blst.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lux::consensus;

namespace {

int g_pass = 0, g_fail = 0;
void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("    ok   %s\n", what.c_str()); return; }
    ++g_fail;
    std::printf("    FAIL %s\n", what.c_str());
}

[[noreturn]] void die(const char* what) {
    std::printf("registration_test: %s\n", what);
    std::exit(2);
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey                       pk{};
};

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0x5A ^ (tag + i));
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

std::vector<std::uint8_t> bytes(const PubKey& k) { return {k.begin(), k.end()}; }

// The proof a registrant makes for its own pair: a signature by sk over the
// 68-byte preimage node ‖ key, under the PROOF domain — never the vote's, which
// is the whole point of there being two tags.
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
    // The proof is only worth anything to this test if the CONFORMANT verifier
    // accepts it. Assert that here, once, so every "genuine proof" below is
    // genuine by the corpus's measure and not by this file's.
    if (bls::pop_verify(node.data(), k.pk.data(), proof.data()) != bls::Pop::Ok)
        die("minted a proof the conformant verifier refuses");
    return proof;
}

Registration reg(const Key& k, const Node& node, std::uint64_t weight) {
    return Registration{node, bytes(k.pk), mint(k, node), weight};
}

const char* pop_name(bls::Pop p) {
    switch (p) {
        case bls::Pop::Ok:         return "ok";
        case bls::Pop::Key:        return "key";
        case bls::Pop::Proof:      return "proof";
        case bls::Pop::Possession: return "possession";
    }
    return "unknown";
}

// One refusal case, named, so a divergence says which clause moved.
void refuses(const std::vector<Registration>& rs, Admission::Why want, const std::string& what) {
    CanonicalSet     set;
    const Admission  a = admit(rs, set);
    const bool       right = (a.why == want);
    check(right && !a, what + " → " + admission_name(want) +
                           (right ? "" : std::string(" (got ") + admission_name(a.why) + ")"));
    check(set.validators.empty() && set.total_weight == 0,
          "  …and a refused call returns no partial set");
}

VotePosition make_pos(std::uint8_t tag) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.canonical_id.fill(std::uint8_t(tag ^ 0xFF));
    p.height = 7;
    p.round  = 2;
    return p;
}

}  // namespace

int main() {
    std::printf("================================================================================\n");
    std::printf("REGISTRATION — the admission door\n");
    std::printf("================================================================================\n");

    // ── 0. The hazard the door exists to close ───────────────────────────────
    // One holder, two identities. The registry is built by hand, exactly as any
    // caller could build it before there was a door.
    {
        std::printf("\n[0] the hazard: two node ids, one key, one signature, a two-signer floor\n");
        const Key  holder = make_key(0x91);
        const Node one = make_node(0x10), two = make_node(0x20);

        Registry keys;
        check(keys.insert(one, holder.pk) && keys.insert(two, holder.pk),
              "a registry accepts one key under two node ids — nothing downstream refuses it");

        const VotePosition              pos = make_pos(0x33);
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, true);
        Signature                       sig{};
        if (bls::sign(holder.sk.data(), msg.data(), msg.size(), sig.data()) != 0) die("sign");

        Cert c;
        c.position  = pos;
        c.threshold = 2;
        c.votes     = {Vote{one, true, {sig.begin(), sig.end()}},
                       Vote{two, true, {sig.begin(), sig.end()}}};
        check(c.verify(keys) == Refusal::None,
              "…and a two-signer certificate VERIFIES on one holder's single signature");

        // The same two claims at the door. Both proofs are genuine — the holder
        // can prove possession for any identity it likes — and the set is still
        // refused, because uniqueness is a property of the set, not of a pair.
        CanonicalSet set;
        const Admission a = admit({reg(holder, one, 1), reg(holder, two, 1)}, set);
        check(a.why == Admission::Why::DuplicateKey, "the door refuses to build that set");
        check(a.node == two && a.holder == one,
              "…naming the node refused and the node already holding the key");
    }

    // ── 1. The happy path, and the shape it guarantees ───────────────────────
    {
        std::printf("\n[1] a proven set is admitted, in canonical order\n");
        const Key a = make_key(1), b = make_key(2), c = make_key(3);
        CanonicalSet set;
        const Admission ok = admit({reg(a, make_node(0x01), 100),
                                    reg(b, make_node(0x02), 200),
                                    reg(c, make_node(0x03), 300)},
                                   set);
        check(bool(ok) && ok.why == Admission::Why::Ok, "three proven registrations are admitted");
        check(set.validators.size() == 3, "three validators seated");
        check(set.total_weight == 600, "total weight is the sum of the admitted weights");

        bool ascending = true, distinct_nodes = true;
        for (std::size_t i = 1; i < set.validators.size(); ++i) {
            if (!(set.validators[i - 1].key < set.validators[i].key)) ascending = false;
            if (set.validators[i - 1].node == set.validators[i].node) distinct_nodes = false;
        }
        check(ascending, "the set is strictly ascending by compressed key — the canonical order");
        check(distinct_nodes, "every validator carries exactly one node id — the merge is gone");

        // The key the set carries is the canonical spelling of the point, and it
        // is the same 48 bytes the proof was made over.
        bool keys_match = false;
        for (const CanonicalValidator& v : set.validators)
            if (v.node == make_node(0x02)) keys_match = (v.key == b.pk);
        check(keys_match, "the seated key is the registrant's own key, re-serialized from the point");
    }

    // ── 2. Possession is required ────────────────────────────────────────────
    {
        std::printf("\n[2] possession: the proof must bind THIS node to THIS key\n");
        const Key  k = make_key(6);
        const Node home = make_node(0x30), elsewhere = make_node(0x31);

        Registration lifted = reg(k, elsewhere, 1);
        lifted.proof = mint(k, home);  // same key, different node, the first node's proof
        refuses({lifted}, Admission::Why::Possession, "a proof lifted from another node");

        // The IETF pubkey-only proof: a statement about a key, so it travels with
        // the key. It proves someone holds the secret and nothing about WHO.
        Registration pubkey_only = reg(k, make_node(0x32), 1);
        std::vector<std::uint8_t> eth2(96);
        if (cevm::crypto::bls::sign(k.sk.data(), k.pk.data(), k.pk.size(), eth2.data()) != 0)
            die("eth2 sign");
        pubkey_only.proof = eth2;
        refuses({pubkey_only}, Admission::Why::Possession, "the pubkey-only proof");

        Registration none = reg(k, make_node(0x33), 1);
        none.proof.clear();
        refuses({none}, Admission::Why::Possession, "no proof at all");

        Registration garbage = reg(k, make_node(0x34), 1);
        garbage.proof.assign(96, 0xAB);
        refuses({garbage}, Admission::Why::Possession, "96 bytes of garbage");

        Registration short_proof = reg(k, make_node(0x35), 1);
        short_proof.proof.pop_back();
        refuses({short_proof}, Admission::Why::Possession, "a 95-byte proof");

        Registration short_key = reg(k, make_node(0x36), 1);
        short_key.key.pop_back();
        refuses({short_key}, Admission::Why::Possession, "a 47-byte key");

        Registration no_key = reg(k, make_node(0x37), 1);
        no_key.key.clear();
        refuses({no_key}, Admission::Why::NoKey, "no key at all");

        Registration identity = reg(k, make_node(0x38), 1);
        identity.key.assign(48, 0x00);
        identity.key[0] = 0xC0;  // compressed G1 infinity
        refuses({identity}, Admission::Why::Possession, "the identity key");

        // The class the proof was refused under travels with the verdict, so an
        // operator is told which leg failed and not merely that one did.
        CanonicalSet    set;
        const Admission a = admit({lifted}, set);
        check(a.possession == bls::Pop::Possession,
              std::string("a decodable but unbinding proof is refused as possession, not encoding "
                          "(got ") + pop_name(a.possession) + ")");
        const Admission b = admit({short_key}, set);
        check(b.possession == bls::Pop::Key, "a wrong-width key is refused as an encoding fault");
    }

    // ── 3. One key, one node ─────────────────────────────────────────────────
    {
        std::printf("\n[3] one key, one node — both proofs genuine, the set still refused\n");
        const Key  k = make_key(5);
        const Node one = make_node(0x40), two = make_node(0x41);

        // Individually sound: this is what makes possession alone insufficient.
        check(bls::pop_verify(one.data(), k.pk.data(), mint(k, one).data()) == bls::Pop::Ok &&
                  bls::pop_verify(two.data(), k.pk.data(), mint(k, two).data()) == bls::Pop::Ok,
              "each registration proves possession on its own");
        refuses({reg(k, one, 1), reg(k, two, 1)}, Admission::Why::DuplicateKey,
                "one key under two nodes");

        // The exact same registration twice is BOTH duplicates at once. Which
        // clause answers is fixed by the order the rule is written in — key
        // before node — and it is fixed the same way in Go, so the two
        // implementations refuse the same bytes with the same word.
        refuses({reg(k, one, 1), reg(k, one, 1)}, Admission::Why::DuplicateKey,
                "one registration presented twice: the key clause answers first");
    }

    // ── 4. One node, one key ─────────────────────────────────────────────────
    {
        std::printf("\n[4] one node, one key — the other axis\n");
        const Node node = make_node(0x50);
        const Key  a = make_key(40), b = make_key(41);
        check(bls::pop_verify(node.data(), a.pk.data(), mint(a, node).data()) == bls::Pop::Ok &&
                  bls::pop_verify(node.data(), b.pk.data(), mint(b, node).data()) == bls::Pop::Ok,
              "each registration proves possession on its own");
        refuses({reg(a, node, 100), reg(b, node, 100)}, Admission::Why::DuplicateNode,
                "one node under two keys");
    }

    // ── 5. Weight ────────────────────────────────────────────────────────────
    {
        std::printf("\n[5] weight: no phantom signers, no total that wrapped\n");
        const Key k = make_key(9), j = make_key(10);
        refuses({reg(k, make_node(0x60), 0)}, Admission::Why::ZeroWeight, "a zero-weight validator");
        refuses({reg(k, make_node(0x61), 5), reg(j, make_node(0x62), 0)},
                Admission::Why::ZeroWeight, "a zero-weight validator beside a good one");

        constexpr std::uint64_t kMax = ~std::uint64_t(0);
        refuses({reg(k, make_node(0x63), kMax), reg(j, make_node(0x64), 1)},
                Admission::Why::WeightOverflow, "a total weight that would wrap");

        CanonicalSet    set;
        const Admission ok = admit({reg(k, make_node(0x65), kMax - 1), reg(j, make_node(0x66), 1)}, set);
        check(bool(ok) && set.total_weight == kMax, "…and the largest total that fits is admitted");
    }

    // ── 5b. The empty set ────────────────────────────────────────────────────
    // Go admits it — Register(nil) is an empty set and no error — so this does
    // too, and the parity is the point: a set with nobody in it is not the door's
    // refusal to make. It dies one layer down, where a quorum of nobody is a
    // configuration error, and that is where it has to die, because the door
    // cannot know whether an empty batch is the whole set or one page of it.
    {
        std::printf("\n[5b] an empty set is admitted, and the gate is where a quorum of nobody dies\n");
        CanonicalSet    set;
        const Admission ok = admit({}, set);
        check(bool(ok) && set.validators.empty() && set.total_weight == 0,
              "no registrations admit to an empty set, as in Go");
        bool refused = false;
        try {
            QuorumCertEngine empty(set.weights(), 1);
            (void)empty;
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        check(refused, "…and the gate refuses to be constructed over it");
    }

    // ── 6. The verdict is a function of the set ──────────────────────────────
    {
        std::printf("\n[6] the refusal does not move with the caller's vector order\n");
        const Key       k = make_key(15);
        const Node      one = make_node(0x70), two = make_node(0x71);
        const Registration a = reg(k, one, 1), b = reg(k, two, 1);

        CanonicalSet    s1, s2;
        const Admission forward  = admit({a, b}, s1);
        const Admission backward = admit({b, a}, s2);
        check(forward.why == backward.why && forward.node == backward.node &&
                  forward.holder == backward.holder,
              "forward and backward refuse the same registration for the same reason");
        check(forward.node == two && forward.holder == one,
              "…and it is the higher node id that is refused, on both");

        // A good set admits to the same bytes in the same order whatever order it
        // arrived in: the canonical order is a property of the set.
        const Key    p = make_key(21), q = make_key(22), r = make_key(23);
        CanonicalSet u, v;
        (void)admit({reg(p, make_node(0x80), 1), reg(q, make_node(0x81), 2), reg(r, make_node(0x82), 3)}, u);
        (void)admit({reg(r, make_node(0x82), 3), reg(p, make_node(0x80), 1), reg(q, make_node(0x81), 2)}, v);
        bool same = u.validators.size() == v.validators.size() && u.total_weight == v.total_weight;
        for (std::size_t i = 0; same && i < u.validators.size(); ++i)
            same = u.validators[i].key == v.validators[i].key &&
                   u.validators[i].node == v.validators[i].node &&
                   u.validators[i].weight == v.validators[i].weight;
        check(same, "two orders of one good set admit to the same set, in the same order");
    }

    // ── 7. The admitted set is the one the gate runs on ──────────────────────
    {
        std::printf("\n[7] the door feeds the gate and the certificate registry\n");
        const std::array<Key, 4> ks = {make_key(70), make_key(71), make_key(72), make_key(73)};
        std::vector<Registration> rs;
        for (std::uint8_t i = 0; i < 4; ++i) rs.push_back(reg(ks[i], make_node(std::uint8_t(0xA0 + i)), 100));

        CanonicalSet    set;
        const Admission ok = admit(rs, set);
        check(bool(ok), "four proven validators are admitted");

        // The gate, constructed over nothing but the admitted set.
        QuorumCertEngine engine(set.weights(), equal_stake_supermajority(4));
        check(engine.validator_count() == 4 && engine.total_stake() == set.total_weight,
              "the gate is constructed over the admitted set and agrees on the total");

        const VotePosition pos = make_pos(0x44);
        check(engine.submit(pos), "a block is pending");
        for (const Key& k : ks) {
            const std::vector<std::uint8_t> msg = canonical_vote_message(pos, true);
            Signature s{};
            if (bls::sign(k.sk.data(), msg.data(), msg.size(), s.data()) != 0) die("sign");
            check(engine.record_vote(pos.block_id, k.pk, s) == VoteResult::Recorded, "  a vote joins");
        }
        check(engine.is_final(pos.block_id, Tier::Quasar), "the admitted set finalizes at Quasar");

        // …and the certificate registry, seated from the same set: four DISTINCT
        // holders behind a four-signer floor, which is what the door bought.
        Registry keys;
        check(set.install(keys), "the admitted set seats the certificate registry");
        check(keys.size() == 4, "four distinct node ids, four distinct keys");

        // …and it is the ONLY set in there. Seating over a live registry would
        // leave a retired validator's node resolvable, so it is refused.
        check(!set.install(keys), "a second set refuses to seat over a live registry");
        Registry stale;
        check(stale.insert(make_node(0xF1), ks[0].pk), "a hand-seated registry");
        check(!set.install(stale), "…and an admitted set will not be added to it");

        Cert c;
        c.position  = pos;
        c.threshold = 4;
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, true);
        for (const CanonicalValidator& v : set.validators) {
            const Key* owner = nullptr;
            for (const Key& k : ks)
                if (k.pk == v.key) owner = &k;
            if (owner == nullptr) die("an admitted key belongs to no test validator");
            Signature s{};
            if (bls::sign(owner->sk.data(), msg.data(), msg.size(), s.data()) != 0) die("sign");
            c.votes.push_back(Vote{v.node, true, {s.begin(), s.end()}});
        }
        std::sort(c.votes.begin(), c.votes.end(),
                  [](const Vote& x, const Vote& y) { return x.node < y.node; });
        check(c.verify(keys) == Refusal::None,
              "a certificate from the admitted set verifies against it");
    }

    std::printf("\n--------------------------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== REGISTRATION: FAIL ====\n"); return 1; }
    std::printf("==== REGISTRATION: PASS — possession required, one key one node, one node one key ====\n");
    return 0;
}
