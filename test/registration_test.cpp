// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// registration_test.cpp — the admission door, against the rule Go writes in
// validator/registration.go.
//
// The properties under test are the ones a door can get wrong, and the first one
// is the reason the door exists at all:
//
//   0. THE HAZARD IS REAL, AND IT IS NOW UNBUILDABLE. Two node ids resolving to
//      ONE key clear a two-signer floor on ONE holder's signature, and the
//      certificate verifier is RIGHT to accept it: it counts what the set it was
//      handed says, and that set says two nodes signed. Nothing downstream can
//      catch it. So the catch is upstream and it is doubled — admit() refuses to
//      build the set, and Registry refuses to seat it however it was built.
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

// A key resolver that answers for SEVERAL node ids with ONE holder's key: the
// set the door exists to keep out of the world. It is a Keys, not a Registry,
// precisely because a Registry can no longer be one — and the hazard has to stay
// demonstrable, or the reason for the lock stops being visible.
struct OneHolder : Keys {
    OneHolder(const PubKey& k, std::vector<Node> ns) : key(k), names(std::move(ns)) {}

    PubKey            key{};
    std::vector<Node> names;

    [[nodiscard]] bool verify(const Node& node,
                              const std::uint8_t* message, std::size_t message_len,
                              const std::uint8_t* signature,
                              std::size_t signature_len) const override {
        if (std::find(names.begin(), names.end(), node) == names.end()) return false;
        if (signature_len != 96) return false;
        return bls::verify(key.data(), message, message_len, signature) == 0;
    }
};

// Can a registry be seated by hand? The question is asked of a TEMPLATE
// parameter on purpose: an access failure during substitution is a false
// concept, where the same expression written against Registry directly is a hard
// error — which is the truth being asserted, but not in a form a test can hold.
template <class R>
concept Seatable = requires(R& r, const Node& n, const PubKey& k) { r.insert(n, k); };

// The same seat, left open — so the detector is known to DISCRIMINATE and the
// assertion about Registry is not a question that always answers no.
struct OpenSeat {
    bool insert(const Node&, const PubKey&) { return true; }
};
static_assert(Seatable<OpenSeat>, "the detector must see a seat that is reachable");

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
    // One holder, two identities — shown to be genuinely dangerous, and then
    // shown to be unreachable by every route into a live Registry.
    {
        std::printf("\n[0] the hazard: two node ids, one key, one signature, a two-signer floor\n");
        const Key  holder = make_key(0x91);
        const Node one = make_node(0x10), two = make_node(0x20);

        const VotePosition              pos = make_pos(0x33);
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, true);
        Signature                       sig{};
        if (bls::sign(holder.sk.data(), msg.data(), msg.size(), sig.data()) != 0) die("sign");

        Cert c;
        c.position  = pos;
        c.threshold = 2;
        c.votes     = {Vote{one, true, {sig.begin(), sig.end()}},
                       Vote{two, true, {sig.begin(), sig.end()}}};

        // THE HAZARD, on a set that says what a hand-built registry used to be
        // able to say. The verifier is not at fault here and this is not a
        // finding against it: it resolved both names, checked a real signature
        // under each, and counted two. The lie is in the set.
        OneHolder hazard{holder.pk, {one, two}};
        check(c.verify(hazard) == Refusal::None,
              "a set answering for two node ids with one key clears a two-signer floor "
              "on ONE signature");

        // ROUTE 1 — the seat itself. There is no hand to build that registry
        // with: seating is private and CanonicalSet::install is its only friend,
        // so the call below is not a refusal at run time, it is not a program.
        static_assert(!Seatable<Registry>,
                      "Registry::insert must be private — install() is the one seating route");
        check(Seatable<OpenSeat> && !Seatable<Registry>,
              "no caller can seat a Registry by hand — insert is private to install()");

        // ROUTE 2 — a canonical set written down by hand. CanonicalSet is a plain
        // aggregate, so this compiles and admit() never saw it; the seat holds
        // the uniqueness rule anyway, and holds it WHOLE.
        CanonicalSet forged;
        forged.validators = {CanonicalValidator{one, holder.pk, 1},
                             CanonicalValidator{two, holder.pk, 1}};
        forged.total_weight = 2;
        Registry keys;
        check(!forged.install(keys), "a forged set — two node ids, one key — seats nothing");
        check(keys.size() == 0, "…and the registry it was offered is still empty");

        // The other axis, forged the same way: one node id under two keys is two
        // signer indices and two shares of the weight under one identity.
        const Key       second = make_key(0x92);
        CanonicalSet    twins;
        twins.validators   = {CanonicalValidator{one, holder.pk, 1},
                              CanonicalValidator{one, second.pk, 1}};
        twins.total_weight = 2;
        Registry twin_keys;
        check(!twins.install(twin_keys), "a forged set — one node id, two keys — seats nothing");
        check(twin_keys.size() == 0, "…and that registry is still empty too");

        // ROUTE 3 — the door. Both proofs are genuine, because the holder can
        // prove possession for any identity it likes, and the set is refused
        // anyway: uniqueness is a property of the set, not of a pair.
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
            QuorumCertEngine empty(set.weights());
            (void)empty;
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        check(refused, "…and the gate refuses to be constructed over it");
    }

    // ── 6. What is, and is not, a function of the set ────────────────────────
    // The stable sort is TOTAL when the node ids are distinct, and only then. Two
    // registrations sharing a node id it cannot separate, so their input order
    // survives into the walk — which is exactly Go's behaviour (SortStableFunc),
    // and the reason the header's claim is scoped rather than absolute.
    {
        std::printf("\n[6] the set decides the verdict; the order can decide the wording\n");
        const Key       k = make_key(15);
        const Node      one = make_node(0x70), two = make_node(0x71);
        const Registration a = reg(k, one, 1), b = reg(k, two, 1);

        CanonicalSet    s1, s2;
        const Admission forward  = admit({a, b}, s1);
        const Admission backward = admit({b, a}, s2);
        check(forward.why == backward.why && forward.node == backward.node &&
                  forward.holder == backward.holder,
              "distinct node ids: forward and backward refuse the same registration "
              "for the same reason");
        check(forward.node == two && forward.holder == one,
              "…and it is the higher node id that is refused, on both");

        // A REPEATED NODE ID — the one input the sort cannot order. Both entries
        // claim node 0x72 and both are faulty, at DIFFERENT clauses: one stakes
        // nothing, the other carries a proof minted for another node. Every
        // per-registration clause answers for its own entry, so whichever is
        // walked first is the one that answers, and the sort will not choose.
        {
            const Key  h = make_key(16), g = make_key(17);
            const Node twin = make_node(0x72), elsewhere = make_node(0x73);
            const Registration weightless = reg(h, twin, 0);
            Registration       unproven   = reg(g, twin, 1);
            unproven.proof                = mint(g, elsewhere);  // genuine, for another node

            CanonicalSet    t1, t2;
            const Admission first  = admit({weightless, unproven}, t1);
            const Admission second = admit({unproven, weightless}, t2);

            // THE PROPERTY THAT HOLDS, and the only one consensus needs: the
            // decision is the set's, and a refusal carries no set either way.
            check(!first && !second, "a repeated node id is refused whichever order it arrives in");
            check(t1.validators.empty() && t1.total_weight == 0 &&
                      t2.validators.empty() && t2.total_weight == 0,
                  "…and neither refusal leaves a partial set behind");

            // THE PROPERTY THAT DOES NOT, pinned so a "fix" that made the sort
            // total would fail here rather than diverge from Go in silence: both
            // refusals name node 0x72, and which fault they name follows the
            // order the caller happened to write.
            check(first.node == twin && second.node == twin,
                  "…both name the node they share");
            check(first.why == Admission::Why::ZeroWeight &&
                      second.why == Admission::Why::Possession,
                  "…while WHICH clause answers follows the order, exactly as it does in Go");
        }

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
        QuorumCertEngine engine(set.weights());
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
        CanonicalSet other;
        other.validators   = {CanonicalValidator{make_node(0xF1), ks[0].pk, 1}};
        other.total_weight = 1;
        Registry stale;
        check(other.install(stale), "a registry seated from some other set");
        check(!set.install(stale), "…and an admitted set will not be added to it");

        // A SEAT THAT FAILS MIDWAY LEAVES NOTHING. The refusal is total for the
        // same reason admission is: a registry holding a PREFIX of a set resolves
        // some of its nodes and none of the rest, which is a validator set nobody
        // chose and whose total the floors were never taken of.
        CanonicalSet doomed;
        doomed.validators   = {CanonicalValidator{make_node(0xE1), ks[0].pk, 1},
                               CanonicalValidator{make_node(0xE2), ks[1].pk, 1},
                               CanonicalValidator{make_node(0xE3), ks[0].pk, 1}};
        doomed.total_weight = 3;
        Registry partial;
        check(!doomed.install(partial), "a set that repeats a key on its third seat is refused");
        check(partial.size() == 0, "…and leaves the registry EMPTY, not holding the two good seats");

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

    // ── 8. The registry is the SECOND wall, and it does not trust the first ──
    // admit() builds a canonical set; install() seats it. CanonicalSet is a plain
    // aggregate, so a set that never went through admit() can be handed to
    // install() by anything that can name the type — a caller reading one off a
    // wire, a future door with a bug in it. The registry therefore decodes every
    // key itself rather than believing the set that carries it, and refuses the
    // whole seating if any one of them is not a key. Seated whole or not at all.
    std::printf("\n[8] a set that did not come through the door is still decoded key by key\n");
    {
        const Key good = make_key(0x71);
        const Node n0 = make_node(0x01), n1 = make_node(0x02);

        const auto seats = [&](const PubKey& second, const std::string& what, bool want) {
            CanonicalSet forged;
            forged.validators.push_back(CanonicalValidator{n0, good.pk, 10});
            forged.validators.push_back(CanonicalValidator{n1, second, 10});
            forged.total_weight = 20;
            Registry keys;
            const bool ok = forged.install(keys);
            check(ok == want, what);
            // Whole or not at all: a refused install leaves NOTHING seated, so the
            // first validator cannot be resolvable while the second is not.
            check(keys.size() == (want ? 2u : 0u),
                  want ? "  …and both seats are taken" : "  …and no partial registry is left behind");
        };

        PubKey not_a_point{};
        not_a_point.fill(0xAB);
        PubKey identity{};
        identity[0] = 0xC0;  // the compressed identity: it verifies ANY message
        PubKey off_subgroup{};
        {
            // On the curve, outside the prime-order subgroup — past the decode
            // clause and into the subgroup one, which is a separate refusal.
            bool found = false;
            for (std::uint32_t x = 1; x < 4096 && !found; ++x) {
                off_subgroup.fill(0);
                off_subgroup[47] = std::uint8_t(x);
                off_subgroup[46] = std::uint8_t(x >> 8);
                off_subgroup[0] |= 0x80;
                blst_p1_affine a;
                found = blst_p1_uncompress(&a, off_subgroup.data()) == BLST_SUCCESS &&
                        !blst_p1_affine_in_g1(&a);
            }
            if (!found) die("no off-subgroup G1 candidate found");
        }

        seats(make_key(0x72).pk, "a set of two real keys seats", true);
        seats(not_a_point, "a key that is not a curve point seats nothing", false);
        seats(identity, "the identity key seats nothing — it would verify any message", false);
        seats(off_subgroup, "a curve point outside the prime-order subgroup seats nothing", false);
        seats(good.pk, "and one key under two node ids seats nothing", false);

        // A registry that already holds a set is not this set: seating is a
        // rotation, not an accumulation.
        {
            CanonicalSet a;
            a.validators.push_back(CanonicalValidator{n0, good.pk, 10});
            a.total_weight = 10;
            Registry keys;
            check(a.install(keys) && keys.size() == 1, "a fresh registry takes a set");
            CanonicalSet b;
            b.validators.push_back(CanonicalValidator{n1, make_key(0x73).pk, 10});
            b.total_weight = 10;
            check(!b.install(keys), "a registry that already holds a set refuses a second");
            check(keys.size() == 1, "  …and keeps the one it had");
        }
    }

    // ── 9. A seated registry refuses a signature that was never a point ──────
    // The certificate verifier asks the registry, and the registry asks blst. A
    // vote carrying 96 bytes that do not decode is a refusal at that leg — never
    // a pairing, and never a skip that would leave the vote uncounted but the
    // certificate still valid.
    std::printf("\n[9] a vote whose signature is not a G2 point is refused, not skipped\n");
    {
        const Key k = make_key(0x81);
        const Node n = make_node(0x11);
        CanonicalSet set;
        set.validators.push_back(CanonicalValidator{n, k.pk, 10});
        set.total_weight = 10;
        Registry keys;
        if (!set.install(keys)) die("install");

        const VotePosition pos = make_pos(0x55);
        Cert c;
        c.position = pos;
        c.threshold = 1;
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
        Signature s{};
        if (bls::sign(k.sk.data(), msg.data(), msg.size(), s.data()) != 0) die("sign");
        c.votes.push_back(Vote{n, true, {s.begin(), s.end()}});
        check(c.verify(keys) == Refusal::None, "the genuine vote verifies against the registry");

        Cert bad = c;
        bad.votes[0].signature.assign(96, 0xCD);
        check(bad.verify(keys) == Refusal::Signature,
              "96 bytes that are not a G2 point are a signature refusal");

        Cert unknown = c;
        unknown.votes[0].node = make_node(0x99);
        check(unknown.verify(keys) == Refusal::Signature,
              "a voter the registry cannot resolve is refused, not skipped");
    }

    // ── 10. Every verdict this door and this verifier can give has a name ────
    // The names are not decoration: conformance_test compares them against the Go
    // corpus, so a table that fell out of step with its enum would report a
    // refusal Go never made and call the two implementations equal.
    std::printf("\n[10] the verdict names are the ones the corpus is compared against\n");
    {
        check(std::string(admission_name(Admission::Why::Ok)) == "ok" &&
                  std::string(admission_name(Admission::Why::NoKey)) == "no_key" &&
                  std::string(admission_name(Admission::Why::ZeroWeight)) == "zero_weight" &&
                  std::string(admission_name(Admission::Why::Possession)) == "possession" &&
                  std::string(admission_name(Admission::Why::DuplicateKey)) == "duplicate_key" &&
                  std::string(admission_name(Admission::Why::DuplicateNode)) == "duplicate_node" &&
                  std::string(admission_name(Admission::Why::WeightOverflow)) == "weight_overflow",
              "every admission verdict has its own name");
        check(std::string(refusal_name(Refusal::None)) == "ok" &&
                  std::string(refusal_name(Refusal::Version)) == "version" &&
                  std::string(refusal_name(Refusal::Role)) == "role" &&
                  std::string(refusal_name(Refusal::Tier)) == "tier" &&
                  std::string(refusal_name(Refusal::ThresholdZero)) == "threshold_zero" &&
                  std::string(refusal_name(Refusal::NoVotes)) == "no_votes" &&
                  std::string(refusal_name(Refusal::Order)) == "order" &&
                  std::string(refusal_name(Refusal::NotAccept)) == "not_accept" &&
                  std::string(refusal_name(Refusal::Signature)) == "signature" &&
                  std::string(refusal_name(Refusal::BelowThreshold)) == "below_threshold" &&
                  std::string(refusal_name(Refusal::Wire)) == "wire",
              "and every certificate refusal has its own name");
    }

    std::printf("\n--------------------------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== REGISTRATION: FAIL ====\n"); return 1; }
    std::printf("==== REGISTRATION: PASS — possession required, one key one node, one node one key ====\n");
    return 0;
}
