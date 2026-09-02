// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// tier_test.cpp — the two finality rungs, with real BLS12-381 keys.
//
// Go has two, and they are not interchangeable (engine/chain VerifyWeighted):
//
//   Nova   — voters ≥ nova_signer_floor(n), stake > floor(total/2). Local
//            execution. Crash-fault-safe by majority intersection, reorgable,
//            and deliberately NOT Byzantine-safe. Authorizes no export.
//   Quasar — voters ≥ two_thirds_count(n), stake > floor(2·total/3). The export
//            rung a bridge, DEX settlement or cross-chain consumer admits on.
//
// Both floors of both rungs come from the live SET. Neither is configured, and
// the export one used to be: it was the engine's alpha constructor parameter,
// which made the number of parties export finality reports a value the operator
// picks — and at alpha = 1 it reports one.
//
// The properties under test are the ones a second rung can get wrong:
//   1. Nova ignites where Quasar does not — the rungs are genuinely distinct.
//   2. A cert cannot forge its tier UPWARD: relabelling a Nova cert Quasar dies
//      on the ⅔ clause, because the verifier re-derives the floor from the live
//      set instead of reading the cert's own claim.
//   3. Relabelling DOWNWARD only under-claims, and is therefore accepted.
//   4. The signer floor is an INDEPENDENT guard at BOTH rungs: one validator
//      holding a stake majority must not self-ignite Nova on its own signature,
//      and one holding two thirds must not export on it either.
//   5. Fail-closed everywhere a floor cannot be asserted.
//   6. The export rung has a THIRD floor, read against the set rather than the
//      votes: below kMinBFTCommittee signers f = (n-1)/3 is 0, so a unanimous
//      certificate carrying every unit of stake tolerates no Byzantine fault.
//      Neither floor above catches it — both shrink with n.
//   7. A validator IS a signer, enforced: a PubKey is an array and is therefore
//      always present, so the constructor decodes it. A seat holding 48 bytes
//      that are not a point would sit in every denominator and never sign.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/threshold.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

struct Key { std::array<std::uint8_t, 32> sk{}; PubKey pk{}; };

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0x5A ^ (tag + i));
    Key k;
    if (bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
    if (bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk"); std::exit(2); }
    return k;
}

VotePosition make_pos(std::uint8_t tag, std::uint64_t height) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.height = height;
    return p;
}

Signature sign_vote(const Key& k, const VotePosition& pos) {
    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    Signature s{};
    if (bls::sign(k.sk.data(), msg.data(), msg.size(), s.data()) != 0) { std::puts("sign"); std::exit(2); }
    return s;
}

std::vector<Key> keyring(std::size_t n) {
    std::vector<Key> ks;
    for (std::size_t i = 0; i < n; ++i) ks.push_back(make_key(std::uint8_t(0xC0 + i)));
    return ks;
}

}  // namespace

int main() {
    std::printf("================== consensus — FINALITY TIERS (Nova / Quasar) ==================\n");

    const std::vector<Key> keys = keyring(5);

    // ── [1] equal stake: the rungs are distinct ──────────────────────────────
    // 5 × 20 = 100. Nova: ≥3 voters and >50. Quasar: ≥4 voters and >66.
    std::printf("\n[1] equal stake (5×20): Nova ignites at 3/60, Quasar needs 4/80\n");
    {
        std::vector<Validator> set;
        for (const Key& k : keys) set.push_back({k.pk, 20});
        QuorumCertEngine e(set);

        check(e.signer_floor(Tier::Nova) == 3 && e.stake_floor(Tier::Nova) == 50,
              "Nova floors are 3 signers / >50 stake");
        check(e.signer_floor(Tier::Quasar) == 4 && e.stake_floor(Tier::Quasar) == 66,
              "Quasar floors are α=4 signers / >66 stake");

        const VotePosition P = make_pos(0x41, 10);
        e.submit(P);
        check(!e.is_final(P.block_id, Tier::Nova), "0 votes: Nova not final (fail-closed)");

        for (int i = 0; i < 3; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        check(e.is_final(P.block_id, Tier::Nova), "3 votes / 60 stake: NOVA final");
        check(!e.is_final(P.block_id, Tier::Quasar), "3 votes / 60 stake: QUASAR not final");
        check(!e.assemble_cert(P.block_id, Tier::Quasar).has_value(), "no Quasar cert at the Nova rung");

        const auto nova = e.assemble_cert(P.block_id, Tier::Nova);
        check(nova.has_value(), "a Nova cert assembles");
        check(nova && e.verify_cert(*nova), "the Nova cert independently RE-VERIFIES");
        check(nova && nova->tier == Tier::Nova && nova->threshold == 3,
              "the Nova cert carries its tier and that tier's floor");

        // (2) FORGING THE TIER UPWARD. Relabel the Nova cert Quasar and give it the
        //     Quasar threshold so it is internally consistent. The verifier re-derives
        //     the ⅔ floor from the live set, so 60 ≤ 66 kills it.
        if (nova) {
            QuorumCert lifted = *nova;
            lifted.tier = Tier::Quasar;
            lifted.threshold = e.signer_floor(Tier::Quasar);
            check(!e.verify_cert(lifted),
                  "a Nova cert relabelled QUASAR fails the ⅔-by-stake clause");
        }

        // Complete the Quasar quorum.
        (void)e.record_vote(P.block_id, keys[3].pk, sign_vote(keys[3], P));
        check(e.is_final(P.block_id, Tier::Quasar), "4 votes / 80 stake: QUASAR final");
        const auto quasar = e.assemble_cert(P.block_id, Tier::Quasar);
        check(quasar && e.verify_cert(*quasar), "the Quasar cert RE-VERIFIES");

        // (3) DOWNWARD is only an under-claim, so it verifies — as in Go.
        if (quasar) {
            QuorumCert lowered = *quasar;
            lowered.tier = Tier::Nova;
            lowered.threshold = e.signer_floor(Tier::Nova);
            check(e.verify_cert(lowered),
                  "a Quasar cert relabelled NOVA only under-claims, so it verifies");
        }

        // A cert whose self-declared threshold is not the tier's floor is refused
        // outright: the two must agree, and the floor is the engine's, not the cert's.
        if (quasar) {
            QuorumCert lying = *quasar;
            lying.threshold = 1;
            check(!e.verify_cert(lying), "a cert cannot declare its own threshold");
        }
    }

    // ── [4] skewed stake: the signer floor is an independent guard ───────────
    // {70,10,10,5,5} = 100. One validator alone holds a stake MAJORITY (70 > 50).
    // The Nova signer floor of 3 is what stops it self-igniting.
    std::printf("\n[4] skewed stake (70,10,10,5,5): a stake majority alone cannot ignite Nova\n");
    {
        const std::uint64_t stakes[5] = {70, 10, 10, 5, 5};
        std::vector<Validator> set;
        for (std::size_t i = 0; i < keys.size(); ++i) set.push_back({keys[i].pk, stakes[i]});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(0x42, 11);
        e.submit(P);
        (void)e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P));
        check(e.voted_stake(P.block_id) == 70 && e.voted_stake(P.block_id) > e.stake_floor(Tier::Nova),
              "one validator's 70 stake IS a strict majority of 100");
        check(!e.is_final(P.block_id, Tier::Nova),
              "…and still does NOT ignite Nova — the signer floor blocks self-finality");

        (void)e.record_vote(P.block_id, keys[1].pk, sign_vote(keys[1], P));
        check(!e.is_final(P.block_id, Tier::Nova), "2 signers: still below the floor of 3");
        (void)e.record_vote(P.block_id, keys[2].pk, sign_vote(keys[2], P));
        check(e.is_final(P.block_id, Tier::Nova), "3 signers / 90 stake: NOVA final");
        check(!e.is_final(P.block_id, Tier::Quasar), "…but 3 signers is below the export floor of 4, so no export");
    }

    // ── [5] fail-closed ─────────────────────────────────────────────────────
    std::printf("\n[5] fail-closed: an unknown block is final at NO tier\n");
    {
        std::vector<Validator> set;
        for (const Key& k : keys) set.push_back({k.pk, 20});
        QuorumCertEngine e(set);
        BlockId unknown{};
        unknown.fill(0xEE);
        check(!e.is_final(unknown, Tier::Nova) && !e.is_final(unknown, Tier::Quasar),
              "unknown block: not final at Nova, not final at Quasar");
        check(!e.assemble_cert(unknown, Tier::Nova).has_value(), "no cert for an unknown block");

        // A tier value that is neither rung is not a rung. Nothing verifies under it.
        const VotePosition P = make_pos(0x43, 12);
        e.submit(P);
        for (int i = 0; i < 4; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        auto c = e.assemble_cert(P.block_id, Tier::Quasar);
        check(c.has_value(), "a Quasar cert assembles");
        if (c) {
            QuorumCert bogus = *c;
            bogus.tier = static_cast<Tier>(4);  // Go's Horizon — not an attestable rung here
            check(!e.verify_cert(bogus), "an unknown tier fails closed");
        }
    }

    // ── [6] the EXPORT signer floor, derived and not configured ─────────────
    // One holder of a hundred of a hundred and four signs alone. It clears the
    // export STAKE floor several times over — floor(2·104/3) = 69 — so a rung
    // that read only stake would export a certificate one key produced, and
    // "Byzantine supermajority" would be a statement about one operator.
    std::printf("\n[6] a lone holder of ⅔ of the stake cannot export\n");
    {
        std::vector<Validator> set;
        for (std::size_t i = 0; i < keys.size(); ++i)
            set.push_back({keys[i].pk, i == 0 ? std::uint64_t(100) : std::uint64_t(1)});
        QuorumCertEngine e(set);

        check(e.total_stake() == 104 && e.stake_floor(Tier::Quasar) == 69,
              "the set is 104 staked and the export stake floor is 69");
        check(e.signer_floor(Tier::Quasar) == two_thirds_count(5) && e.signer_floor(Tier::Quasar) == 4,
              "the export signer floor is derived from the set: floor(2·5/3)+1 = 4");

        const VotePosition P = make_pos(0x61, 21);
        e.submit(P);
        (void)e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P));
        check(e.voted_stake(P.block_id) == 100, "the whale alone carries 100 of 104");
        check(!e.is_final(P.block_id, Tier::Quasar),
              "one signer holding ⅔ of the stake is NOT export-final — the count refuses it");
        check(!e.assemble_cert(P.block_id, Tier::Quasar).has_value(),
              "and no export certificate assembles from it");

        // Two more minimum registrations: still one short of four.
        for (int i = 1; i <= 2; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        check(!e.is_final(P.block_id, Tier::Quasar), "three of five is still below the floor");

        // At the floor the same stake carries — the count was the binding clause.
        (void)e.record_vote(P.block_id, keys[3].pk, sign_vote(keys[3], P));
        check(e.is_final(P.block_id, Tier::Quasar),
              "four distinct signers holding 103 of 104 export");
        const auto cert = e.assemble_cert(P.block_id, Tier::Quasar);
        check(cert.has_value() && cert->threshold == 4 && cert->voters.size() == 4,
              "the certificate declares the derived floor, and carries it");
        check(cert.has_value() && e.verify_cert(*cert), "and it re-verifies against the set");
    }

    // ── [7] the count alone does not export either ──────────────────────────
    // The mirror: four LIGHT signers meet the count floor exactly and hold four
    // of a hundred and four. Neither half of the rule is sufficient alone.
    std::printf("\n[7] meeting the count without the stake does not export\n");
    {
        std::vector<Validator> set;
        for (std::size_t i = 0; i < keys.size(); ++i)
            set.push_back({keys[i].pk, i == 0 ? std::uint64_t(100) : std::uint64_t(1)});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(0x71, 22);
        e.submit(P);
        for (std::size_t i = 1; i < keys.size(); ++i)
            (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        check(e.distinct_voters(P.block_id) == 4 && e.voted_stake(P.block_id) == 4,
              "four distinct signers carrying four of 104");
        check(!e.is_final(P.block_id, Tier::Quasar),
              "the count floor is met and the stake floor is not — refused");
    }

    // ── [8] the export rung's floor on the SET ─────────────────────────────
    // A supermajority is a claim about a fault budget: f = (n-1)/3 validators may
    // be arbitrarily malicious and the rest still agree on one history. Below four
    // signers that budget is ZERO, so a unanimous certificate carrying every unit
    // of stake tolerates nothing and one compromised key among its signers forges
    // it outright.
    //
    // Neither floor above catches it, and that is why it is a separate clause:
    // both are read over n and both shrink with it. At n=1, two_thirds_count(1) is
    // one signature and floor(2·w/3) is two thirds of that signer's own stake, so
    // the rung's whole rule is satisfied by the party it is supposed to constrain.
    std::printf("\n[8] the export rung refuses a set with no Byzantine fault budget\n");
    for (std::uint32_t n = 1; n < kMinBFTCommittee; ++n) {
        std::vector<Validator> set;
        for (std::uint32_t i = 0; i < n; ++i) set.push_back({keys[i].pk, 100});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(std::uint8_t(0x80 + n), 30 + n);
        e.submit(P);
        for (std::uint32_t i = 0; i < n; ++i)
            (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));

        const std::string at = " (n=" + std::to_string(n) + ")";
        // Both quorum floors are MET, so neither can be what refuses it.
        check(e.distinct_voters(P.block_id) >= e.signer_floor(Tier::Quasar),
              "unanimity meets the export count floor" + at);
        check(e.voted_stake(P.block_id) > e.stake_floor(Tier::Quasar),
              "unanimity clears the export stake floor" + at);
        check(!e.is_final(P.block_id, Tier::Quasar),
              "and the export rung refuses it anyway" + at);
        // Nova is untouched: it authorizes only local execution the chain can
        // still reorg away, and a small chain has to be able to make progress.
        check(e.is_final(P.block_id, Tier::Nova), "Nova still ignites" + at);
        // The floor is stated as itself, not smuggled into the voter floor.
        check(e.committee_floor(Tier::Quasar) == kMinBFTCommittee &&
                  e.committee_floor(Tier::Nova) == 1,
              "the committee floor is the export rung's alone" + at);
        // And the same set cannot get its certificate in through the other door.
        std::vector<Validator> wider;
        for (std::uint32_t i = 0; i < kMinBFTCommittee; ++i) wider.push_back({keys[i].pk, 100});
        QuorumCertEngine big(wider);
        const VotePosition W = make_pos(std::uint8_t(0x90 + n), 40 + n);
        big.submit(W);
        for (std::uint32_t i = 0; i < n; ++i)
            (void)big.record_vote(W.block_id, keys[i].pk, sign_vote(keys[i], W));
        QuorumCert forged{};
        forged.version     = kQuorumCertVersion;
        forged.type        = kQCFinality;
        forged.tier        = Tier::Quasar;
        forged.position    = P;
        forged.threshold   = e.signer_floor(Tier::Quasar);
        for (std::uint32_t i = 0; i < n; ++i) forged.voters.push_back(keys[i].pk);
        check(!e.verify_cert(forged), "and verify_cert refuses it at the same floor" + at);
    }

    // At the floor the same shape carries: this is a floor on the set, not a ban
    // on small chains certifying anything.
    {
        std::vector<Validator> set;
        for (std::uint32_t i = 0; i < kMinBFTCommittee; ++i) set.push_back({keys[i].pk, 100});
        QuorumCertEngine e(set);
        const VotePosition P = make_pos(0x8F, 39);
        e.submit(P);
        for (std::uint32_t i = 0; i < kMinBFTCommittee; ++i)
            (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        check(e.is_final(P.block_id, Tier::Quasar),
              "the minimum Byzantine committee exports");
        const auto cert = e.assemble_cert(P.block_id, Tier::Quasar);
        check(cert.has_value() && e.verify_cert(*cert), "and its certificate re-verifies");
    }

    // ── [9] a validator IS a signer, enforced at construction ───────────────
    // A PubKey is an array: it is always present, and presence proves nothing.
    // Forty-eight zero bytes are a well-formed value and not a point of G1, so
    // such a seat would hold stake in every denominator and never produce a
    // signature this engine accepts — the spectator Go and Rust carry explicitly
    // and this implementation must refuse rather than strand.
    std::printf("\n[9] a seat whose key is not a point is refused at construction\n");
    {
        const PubKey dead{};  // 48 zero bytes: present, well-formed, not a point
        check(!bls::key_validate(dead.data()), "the identity-shaped key does not validate");
        bool threw = false;
        try {
            std::vector<Validator> set;
            for (std::size_t i = 0; i < 3; ++i) set.push_back({keys[i].pk, 100});
            set.push_back({dead, 100});
            QuorumCertEngine e(set);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        check(threw, "a set carrying a dead key does not construct");

        // A key that is the right width and simply is not on the curve, and one
        // that is a real point spelled non-canonically, are refused for the same
        // reason at the same door.
        PubKey garbage{};
        garbage.fill(0xAB);
        check(!bls::key_validate(garbage.data()), "a shaped non-point does not validate");
        threw = false;
        try {
            QuorumCertEngine e(std::vector<Validator>{{keys[0].pk, 100}, {garbage, 100}});
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        check(threw, "and a set carrying it does not construct either");

        // The clause does not touch a set of real keys.
        check(bls::key_validate(keys[0].pk.data()), "a real validator key validates");
    }

    // ── [10] verify_cert's refusal table, clause by clause ──────────────────
    // A portable certificate arrives from the wire, so every field on it is an
    // adversary's choice. Each clause of verify_cert is the answer to one such
    // choice, and each is checked here against a certificate that is otherwise
    // VALID — one edit from a cert the same engine accepts, so a clause that
    // stopped refusing could not hide behind another. This is the C++ reading of
    // Go's ErrQC* table (engine/chain.QuorumCert.Verify / VerifyWeighted) and of
    // Rust's Cert rejects.
    std::printf("\n[10] every clause of verify_cert refuses, one edit from a valid cert\n");
    {
        std::vector<Validator> set;
        for (const Key& k : keys) set.push_back({k.pk, 20});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(0xA0, 50);
        e.submit(P);
        for (int i = 0; i < 4; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        const auto assembled = e.assemble_cert(P.block_id, Tier::Quasar);
        check(assembled.has_value() && e.verify_cert(*assembled),
              "the unedited certificate verifies — every refusal below is ONE edit from it");
        if (!assembled) { std::printf("cannot continue without a base cert\n"); return 1; }
        const QuorumCert base = *assembled;

        const auto refuses = [&](QuorumCert c, const std::string& what) {
            check(!e.verify_cert(c), what);
        };

        { QuorumCert c = base; c.version = kQuorumCertVersion + 1; refuses(c, "a wrong version"); }
        { QuorumCert c = base; c.type = kQCFinality + 1; refuses(c, "a wrong role byte"); }
        { QuorumCert c = base; c.tier = static_cast<Tier>(0); refuses(c, "a tier that is neither rung"); }
        { QuorumCert c = base; c.threshold = 0; refuses(c, "a threshold of zero"); }
        { QuorumCert c = base; c.threshold = base.threshold + 1;
          refuses(c, "a threshold above the floor this set derives"); }
        { QuorumCert c = base; c.voters.clear(); refuses(c, "no voters at all"); }
        { QuorumCert c = base; c.voters[1] = c.voters[0];
          refuses(c, "a duplicate voter — one signature counted twice"); }
        { QuorumCert c = base; std::swap(c.voters[0], c.voters[1]);
          refuses(c, "voters out of canonical ascending order"); }
        // The out-of-set voter must still be in ASCENDING order, or the order
        // clause refuses it first and this clause is never reached. Substituting
        // and re-sorting keeps every other field of the cert valid.
        { QuorumCert c = base; c.voters.back() = make_key(0x2A).pk;
          std::sort(c.voters.begin(), c.voters.end());
          refuses(c, "a voter that is not in the set"); }
        { QuorumCert c = base; c.voters.pop_back();
          refuses(c, "one voter short of the tier's distinct-signer floor"); }
        { QuorumCert c = base; c.aggregate_sig.fill(0xAB);
          refuses(c, "an aggregate signature that is not a G2 point"); }
        { QuorumCert c = base; c.aggregate_sig[95] ^= 0x01;
          refuses(c, "an aggregate signature with one bit flipped"); }
        { QuorumCert c = base; c.position.height ^= 1;
          refuses(c, "a position the signatures were not cast over"); }
        // The stake floor is STRICT and is recomputed from the set, never read off
        // the cert: a cert that reports its own stake as a supermajority does not
        // get one. Four of five equal seats is 80 of 100, which clears >66; three
        // is 60, which does not — and it is the recomputed 60 that decides, not the
        // 80 still written on the cert.
        {
            QuorumCert c = base;
            c.voters.pop_back();
            c.threshold = 3;
            check(c.voted_stake == 80 && e.stake_floor(Tier::Quasar) == 66,
                  "the cert still CLAIMS 80 against a floor of 66");
            check(!e.verify_cert(c),
                  "and is refused anyway — the tally is recomputed from the set");
        }
    }

    // The stake floor binding ALONE. Every other clause has to pass for it to be
    // the one that refuses: the right count of distinct in-set voters, in order,
    // the derived threshold, a genuine aggregate over the canonical message — and
    // four light seats out of a hundred and four still do not carry two thirds of
    // the weight. This is scenario [7] read at the certificate rather than at the
    // tally, and it is the clause a verifier that trusted cert.voted_stake would
    // skip.
    {
        std::vector<Validator> set;
        for (std::size_t i = 0; i < keys.size(); ++i)
            set.push_back({keys[i].pk, i == 0 ? std::uint64_t(100) : std::uint64_t(1)});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(0xA5, 51);
        QuorumCert c{};
        c.version   = kQuorumCertVersion;
        c.type      = kQCFinality;
        c.tier      = Tier::Quasar;
        c.position  = P;
        c.threshold = e.signer_floor(Tier::Quasar);

        std::vector<PubKey> light;
        for (std::size_t i = 1; i < keys.size(); ++i) light.push_back(keys[i].pk);
        std::sort(light.begin(), light.end());
        c.voters = light;

        std::vector<std::uint8_t> sigs;
        for (const PubKey& pk : light) {
            const Key* owner = nullptr;
            for (const Key& k : keys)
                if (k.pk == pk) owner = &k;
            const Signature s = sign_vote(*owner, P);
            sigs.insert(sigs.end(), s.begin(), s.end());
        }
        if (bls::aggregate_sigs(sigs.data(), light.size(), c.aggregate_sig.data()) != 0) {
            std::puts("aggregate_sigs"); std::exit(2);
        }

        check(c.voters.size() == e.signer_floor(Tier::Quasar),
              "four genuine in-set signers, exactly the export count floor");
        check(e.total_stake() == 104 && e.stake_floor(Tier::Quasar) == 69,
              "carrying four of a hundred and four, against a floor of 69");
        check(!e.verify_cert(c),
              "the certificate is refused on the STAKE floor alone — every other clause passed");
    }

    // ── [11] the set the gate is built on, refused at construction ──────────
    // Every one of these would be a floor read against a denominator that does
    // not describe the set. They are refused where the set is stated rather than
    // where a certificate is judged, because by then the total is already wrong.
    std::printf("\n[11] a set the floors could not be read against does not construct\n");
    {
        const auto refuses = [](std::vector<Validator> set, const std::string& what) {
            bool threw = false;
            try { QuorumCertEngine e(std::move(set)); } catch (const std::invalid_argument&) { threw = true; }
            check(threw, what);
        };
        refuses({}, "an empty validator set");
        refuses({{keys[0].pk, 100}, {keys[1].pk, 0}},
                "a seat with zero stake — it would raise the signer count and not the weight");
        refuses({{keys[0].pk, 100}, {keys[0].pk, 100}},
                "one key seated twice — two signer indices on one signature");
        refuses({{keys[0].pk, UINT64_MAX}, {keys[1].pk, 1}},
                "a total stake that overflows — a wrapped total is a floor that lies");

        // And the set that says none of those things constructs, with the total it
        // was given.
        QuorumCertEngine ok(std::vector<Validator>{{keys[0].pk, 1}, {keys[1].pk, 2}, {keys[2].pk, 3}});
        check(ok.total_stake() == 6 && ok.validator_count() == 3,
              "a well-formed set carries exactly the stake it was handed");
    }

    // ── [12] the pending-block bookkeeping ──────────────────────────────────
    // The gate is asked about blocks it has never seen and about blocks it has
    // been told about twice. Neither may invent a tally.
    std::printf("\n[12] submit is idempotent, drop is reported, an unknown block tallies zero\n");
    {
        std::vector<Validator> set;
        for (const Key& k : keys) set.push_back({k.pk, 20});
        QuorumCertEngine e(set);

        BlockId unknown{};
        unknown.fill(0xD0);
        check(e.distinct_voters(unknown) == 0 && e.voted_stake(unknown) == 0,
              "an unknown block has no voters and no stake");
        check(!e.position(unknown).has_value(), "and no position");
        check(!e.drop(unknown), "dropping a block that was never pending reports nothing dropped");

        const VotePosition P = make_pos(0xB0, 60);
        check(e.submit(P), "the first submit accepts the position");
        check(!e.submit(P), "a second submit of the same block is refused, not re-armed");
        check(e.position(P.block_id).has_value() && e.position(P.block_id)->height == 60,
              "and the position it holds is the one it was given");

        (void)e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P));
        check(e.distinct_voters(P.block_id) == 1 && e.voted_stake(P.block_id) == 20,
              "one vote is one voter and that voter's stake");
        // A re-submit must not have reset the tally either.
        check(!e.submit(P), "re-submitting a block that already has votes is still refused");
        check(e.distinct_voters(P.block_id) == 1, "and the votes it already holds survive it");

        check(e.drop(P.block_id), "dropping a pending block reports that it was dropped");
        check(e.distinct_voters(P.block_id) == 0 && !e.position(P.block_id).has_value(),
              "and the block is gone with its tally");
        check(e.submit(P), "so the same position can be armed again");
    }

    // ── [13] the vote door ──────────────────────────────────────────────────
    // record_vote's answers are the gate's account of what it did with a vote, and
    // a caller that cannot tell "counted" from "ignored" cannot tell a live tally
    // from a stalled one.
    std::printf("\n[13] every answer record_vote can give\n");
    {
        std::vector<Validator> set;
        for (const Key& k : keys) set.push_back({k.pk, 20});
        QuorumCertEngine e(set);

        const VotePosition P = make_pos(0xC1, 70);
        BlockId unknown{};
        unknown.fill(0xE1);
        check(e.record_vote(unknown, keys[0].pk, sign_vote(keys[0], P)) == VoteResult::RejectedNoSuchBlock,
              "a vote for a block the gate never saw is refused");

        e.submit(P);
        const Key outsider = make_key(0x2B);
        check(e.record_vote(P.block_id, outsider.pk, sign_vote(outsider, P)) ==
                  VoteResult::RejectedUnknownValidator,
              "a vote from a key that holds no stake is refused");
        check(e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P)) == VoteResult::Recorded,
              "an in-set vote is recorded");
        check(e.record_vote(P.block_id, keys[0].pk, sign_vote(keys[0], P)) == VoteResult::Duplicate,
              "and a replay of it is a duplicate, never a second count");
        check(e.distinct_voters(P.block_id) == 1, "so the tally still holds one voter");

        // A forged signature joins as a candidate and is evicted at the gate, where
        // the one aggregate pairing is spent — so the refusal shows up as a tally
        // that does not clear, and the forger's stake is refunded rather than
        // counted.
        for (int i = 1; i < 4; ++i) (void)e.record_vote(P.block_id, keys[i].pk, sign_vote(keys[i], P));
        Signature forged = sign_vote(keys[4], P);
        forged[0] ^= 0x01;
        (void)e.record_vote(P.block_id, keys[4].pk, forged);
        check(e.distinct_voters(P.block_id) == 5, "the forged vote joins as a candidate");
        check(e.is_final(P.block_id, Tier::Quasar),
              "the four genuine votes still export");
        check(e.distinct_voters(P.block_id) == 4 && e.voted_stake(P.block_id) == 80,
              "and the forgery was evicted at the gate, its stake refunded");
        // Asking again is the same answer over a tally already certified: the one
        // aggregate pairing is not re-spent, and an eviction that already happened
        // does not happen twice.
        check(e.is_final(P.block_id, Tier::Quasar) && e.distinct_voters(P.block_id) == 4,
              "asking a second time gives the same answer over the same voters");
        // Now the tally is settled, so a later vote pays its own pairing.
        check(e.record_vote(P.block_id, keys[4].pk, sign_vote(keys[4], P)) == VoteResult::Recorded,
              "a genuine late vote joins a settled tally");
        Signature forged2 = sign_vote(keys[4], P);
        forged2[0] ^= 0x02;
        QuorumCertEngine e2(set);
        const VotePosition Q = make_pos(0xC2, 71);
        e2.submit(Q);
        for (int i = 0; i < 4; ++i) (void)e2.record_vote(Q.block_id, keys[i].pk, sign_vote(keys[i], Q));
        check(e2.is_final(Q.block_id, Tier::Quasar), "a clean tally settles");
        check(e2.record_vote(Q.block_id, keys[4].pk, forged2) == VoteResult::RejectedBadSignature,
              "and a forged late vote is refused outright at the settled tally");
    }

    std::printf("\n--------------------------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== FINALITY TIERS: FAIL ====\n"); return 1; }
    std::printf("==== FINALITY TIERS: PASS — two rungs, no upward forgery, floor holds ====\n");
    return 0;
}
