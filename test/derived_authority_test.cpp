// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// derived_authority_test.cpp — a certificate states its quorum; it does not
// choose it.
//
// The floor a certificate is counted against is a function of the SET it is
// weighed against and the RUNG it attests. The threshold field carries that
// number so a reader knows what was required, and the weighted verifier checks
// the field against what the set actually derives — so the field is a claim,
// never a value the verifier adopts.
//
// Without the clause the field is load-bearing: Cert::verify's last clause counts
// distinct valid accepts against the certificate's OWN threshold, so one
// declaring 1 clears it on a single signature. That is the whole of the structural
// predicate's answer, and a node that admitted a gossiped certificate on it would
// be admitting a quorum the certificate wrote for itself.
//
// This file also holds the OTHER half: that the portable certificate has a
// weighted verifier at all. It used to have only verify(), so nothing on this side
// could weigh a gossiped certificate against a validator set — Go's gossip path
// could, and a certificate two implementations admit and one cannot weigh is not
// one rule.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/cert.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/registration.hpp"
#include "lux/consensus/threshold.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>

using namespace lux::consensus;

namespace {

int g_pass = 0, g_fail = 0;

void check(bool ok, const std::string& what) {
    (ok ? g_pass : g_fail)++;
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey                       pk{};
};

Key make_key(std::uint8_t seed) {
    std::array<std::uint8_t, 32> s{};
    s.fill(seed);
    Key k;
    if (bls::keygen(s.data(), k.sk.data()) != 0) std::exit(2);
    if (bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) std::exit(2);
    return k;
}

Node node_of(std::uint8_t i) {
    Node n{};
    n[kNodeLen - 1] = i;
    return n;
}

// The row's weighted set, read by node id — three projections of ONE set.
class Weights : public Stake {
public:
    Weights(std::map<Node, std::uint64_t> w, std::uint64_t total, std::uint32_t n)
        : w_(std::move(w)), total_(total), n_(n) {}
    [[nodiscard]] std::uint64_t weight(const Node& node) const override {
        const auto it = w_.find(node);
        return it == w_.end() ? 0 : it->second;
    }
    [[nodiscard]] std::uint64_t signer_stake() const override { return total_; }
    [[nodiscard]] std::uint32_t signer_count() const override { return n_; }

private:
    std::map<Node, std::uint64_t> w_;
    std::uint64_t                 total_;
    std::uint32_t                 n_;
};

// A committee of n equal seats, and the objects a portable certificate is weighed
// against: the registry that resolves a node to its key, and the set that weighs it.
struct Fixture {
    std::vector<Key>              keys;
    Registry                      registry;
    std::map<Node, std::uint64_t> weights;
    std::uint64_t                 total = 0;
    std::uint32_t                 n     = 0;
};

Fixture committee(std::uint32_t n, std::uint64_t weight) {
    Fixture f;
    f.n = n;
    CanonicalSet admitted;
    for (std::uint32_t i = 0; i < n; ++i) {
        f.keys.push_back(make_key(std::uint8_t(0xD0 + i)));
        const Node id = node_of(std::uint8_t(i + 1));
        f.weights[id] = weight;
        f.total += weight;
        admitted.validators.push_back(CanonicalValidator{id, f.keys[i].pk, weight});
    }
    admitted.total_weight = f.total;
    if (!admitted.install(f.registry)) std::exit(2);
    return f;
}

VotePosition make_pos() {
    VotePosition p{};
    p.height = 9;
    p.round  = 1;
    p.chain_id.fill(0x07);
    return p;
}

// A certificate from the first k seats, declaring `threshold`.
Cert cert_of(const Fixture& f, Tier tier, std::uint32_t k, std::uint32_t threshold) {
    Cert c;
    c.tier      = tier;
    c.position  = make_pos();
    c.threshold = threshold;
    const std::vector<std::uint8_t> msg = c.message();
    for (std::uint32_t i = 0; i < k; ++i) {
        Signature sig{};
        if (bls::sign(f.keys[i].sk.data(), msg.data(), msg.size(), sig.data()) != 0) std::exit(2);
        c.votes.push_back(Vote{node_of(std::uint8_t(i + 1)), true,
                               std::vector<std::uint8_t>(sig.begin(), sig.end())});
    }
    return c;
}

}  // namespace

int main() {
    std::printf("========== consensus — DERIVED CERTIFICATE AUTHORITY ==========\n");

    // ── one definition of the floor ──────────────────────────────────────────
    std::printf("\n[1] the floor is the rung's arithmetic over the set, and nothing else\n");
    {
        bool nova_ok = true, quasar_ok = true;
        for (std::uint32_t n = 1; n <= 64; ++n) {
            nova_ok   = nova_ok && signer_floor(Tier::Nova, n) == nova_signer_floor(n);
            quasar_ok = quasar_ok && signer_floor(Tier::Quasar, n) == two_thirds_count(n);
        }
        check(nova_ok, "the accept rung derives nova_signer_floor(n) for every n up to 64");
        check(quasar_ok, "the export rung derives two_thirds_count(n) for every n up to 64");
        QuorumCertEngine e(std::vector<Validator>{{make_key(0xE1).pk, 1}, {make_key(0xE2).pk, 1},
                                                  {make_key(0xE3).pk, 1}, {make_key(0xE4).pk, 1}});
        check(e.signer_floor(Tier::Quasar) == signer_floor(Tier::Quasar, 4) &&
                  e.signer_floor(Tier::Nova) == signer_floor(Tier::Nova, 4),
              "the aggregate engine reads the SAME definition the portable certificate does");

        // A tier byte that is neither rung has no floor and must get none. It used
        // to fall through to Nova's — the accept rung's bar handed to a rung that
        // does not exist — where Go and Rust both answer zero and every caller reads
        // zero as a refusal.
        bool unknown_ok = true;
        for (std::uint32_t n = 1; n <= 64; ++n)
            for (std::uint8_t t : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{4},
                                   std::uint8_t{255}})
                unknown_ok = unknown_ok && signer_floor(static_cast<Tier>(t), n) == 0;
        check(unknown_ok, "a rung that is not nova or quasar derives no floor at all");
    }

    // ── the portable certificate is weighed, not merely parsed ───────────────
    std::printf("\n[2] the export rung, over a gossiped certificate\n");
    {
        const Fixture f = committee(4, 100);
        const Weights w(f.weights, f.total, f.n);

        const Cert honest = cert_of(f, Tier::Quasar, 4, signer_floor(Tier::Quasar, 4));
        check(honest.verify(f.registry) == Refusal::None, "four of four is structurally sound");
        check(honest.verify_weighted(f.registry, w) == Refusal::None,
              "and the set authorizes it: four hundred of four hundred over a committee of four");

        // Two signers: structurally sound against its own declaration, and refused
        // by the SET. This is the pair that says why verify() is not an accept rule.
        const Cert two = cert_of(f, Tier::Quasar, 2, 2);
        check(two.verify(f.registry) == Refusal::None,
              "a two-signer certificate declaring two clears the structural predicate");
        check(two.verify_weighted(f.registry, w) == Refusal::ThresholdNotDerived,
              "and the set refuses it: two is not the quorum a committee of four derives");
    }

    // ── the declaration is a claim, in both directions ───────────────────────
    std::printf("\n[3] a certificate states its quorum; it does not choose it\n");
    {
        const Fixture f = committee(4, 100);
        const Weights w(f.weights, f.total, f.n);

        // THE UNDER-CLAIM. Every signature verifies and the stake is unanimous; the
        // only thing wrong is the number. Without the derived clause verify() counts
        // four accepts against a declared one and answers None.
        Cert under = cert_of(f, Tier::Quasar, 4, 1);
        check(under.verify(f.registry) == Refusal::None,
              "the structural predicate accepts a certificate declaring a quorum of one");
        check(under.verify_weighted(f.registry, w) == Refusal::ThresholdNotDerived,
              "the set does not: an under-claim is refused on the derived clause");

        // THE OVER-CLAIM, for the same reason in the other direction. Four signatures
        // clear a declared four, so the count clause has nothing to say and the
        // derived clause is the only thing refusing it.
        Cert over = cert_of(f, Tier::Quasar, 4, 4);
        check(over.verify(f.registry) == Refusal::None,
              "the structural predicate accepts an over-claim it can satisfy by counting");
        check(over.verify_weighted(f.registry, w) == Refusal::ThresholdNotDerived,
              "the set refuses a quorum it does not require — the rule is equality");

        // The rule is one rule and not an export special case.
        const Fixture g = committee(5, 100);
        const Weights gw(g.weights, g.total, g.n);
        const Cert nova = cert_of(g, Tier::Nova, 3, signer_floor(Tier::Nova, 5));
        check(nova.verify_weighted(g.registry, gw) == Refusal::None,
              "the accept rung admits three of five declaring the floor it derives");
        Cert nova_under = cert_of(g, Tier::Nova, 3, 1);
        check(nova_under.verify_weighted(g.registry, gw) == Refusal::ThresholdNotDerived,
              "and refuses the same votes declaring a quorum of one");
    }

    // ── the floors the derived clause does not replace ───────────────────────
    std::printf("\n[4] the rung's own floors, recomputed from the set\n");
    {
        // A committee of three is below the Byzantine floor: f = (n-1)/3 is zero, so
        // a unanimous export certificate over it tolerates no fault at all.
        const Fixture small = committee(3, 100);
        const Weights sw(small.weights, small.total, small.n);
        const Cert unanimous = cert_of(small, Tier::Quasar, 3, signer_floor(Tier::Quasar, 3));
        check(unanimous.verify_weighted(small.registry, sw) == Refusal::BelowThreshold,
              "three unanimous parties are not a Byzantine committee, whatever they declare");

        // A lone holder of a stake majority must not ignite the accept rung.
        Fixture whale = committee(5, 1);
        whale.weights[node_of(1)] = 100;
        whale.total               = 104;
        const Weights ww(whale.weights, whale.total, whale.n);
        const Cert alone = cert_of(whale, Tier::Nova, 1, signer_floor(Tier::Nova, 5));
        check(alone.verify_weighted(whale.registry, ww) == Refusal::BelowThreshold,
              "a stake majority on one signature does not ignite local execution");

        // And the stake half, isolated: the four light seats meet the export count
        // floor and hold four units of a hundred and four.
        Cert light;
        light.tier      = Tier::Quasar;
        light.position  = make_pos();
        light.threshold = signer_floor(Tier::Quasar, 5);
        const std::vector<std::uint8_t> msg = light.message();
        for (std::uint32_t i = 1; i < 5; ++i) {
            Signature sig{};
            if (bls::sign(whale.keys[i].sk.data(), msg.data(), msg.size(), sig.data()) != 0)
                std::exit(2);
            light.votes.push_back(Vote{node_of(std::uint8_t(i + 1)), true,
                                       std::vector<std::uint8_t>(sig.begin(), sig.end())});
        }
        check(light.votes.size() == signer_floor(Tier::Quasar, 5),
              "the four minimum registrations meet the export count floor");
        check(light.verify_weighted(whale.registry, ww) == Refusal::StakeBelowSupermajority,
              "and are refused on stake alone — neither half of the rule is sufficient");
    }

    // ── an unresolved set derives no floor, and that is not a pass ───────────
    std::printf("\n[5] an unresolved set\n");
    {
        const Fixture f = committee(4, 100);
        const Weights unresolved(f.weights, f.total, 0);
        const Cert c = cert_of(f, Tier::Quasar, 4, 1);
        const Refusal why = c.verify_weighted(f.registry, unresolved);
        check(why != Refusal::None, "a set that reports no signers refuses, it does not pass");
        check(why != Refusal::ThresholdNotDerived,
              "and is not named by the derived clause — an unknown set derives no number");
    }

    std::printf("\n--------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== DERIVED AUTHORITY: FAIL ====\n"); return 1; }
    std::printf("==== DERIVED AUTHORITY: PASS ====\n");
    return 0;
}
