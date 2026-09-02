// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// bench_trilang.cpp — the C++ leg of the three-language CPU comparison.
//
// It times exactly the operations the Go leg (engine/chain/bench_trilang_test.go)
// and the Rust leg (pkg/rust/benches/consensus_bench.rs) time, over the SAME
// 226-byte canonical vote message, under the SAME domain tag, on the SAME blst
// v0.3.16. What differs between the three numbers is then the language and the
// binding, which is the thing being measured.
//
// TWO CERTIFICATE PREDICATES ARE TIMED, deliberately, and they are NOT two
// measurements of the same thing:
//
//   Cert::verify        — the PORTABLE certificate (cert.hpp): node ids and a
//                         signature per voter, one pairing PER VOTE. This is
//                         the object Go assembles and Rust decodes, and since
//                         it now passes the Go corpus clause by clause, this
//                         row is comparable to Go's QuorumCert.Verify and
//                         Rust's Cert::verify. It is the only certificate row
//                         that is.
//   verify_cert         — QuorumCertEngine::verify_cert, the C++ LOCAL gate:
//                         public keys and ONE aggregate signature, one pairing
//                         total. No Go or Rust counterpart exists, because
//                         neither implementation has this object. Timed so the
//                         cost of the choice is visible, never as "C++ verifies
//                         certificates n times faster".
//
// AGGREGATION IS TIMED THREE WAYS for the same reason. The three legs were
// handing their aggregators different inputs under one name: Rust summed
// already-decompressed signatures with the group check off, Go summed
// decompressed signatures with it on, and C++ summed COMPRESSED bytes and paid
// to decompress every one. That is a sixtyfold spread with no language in it.
// Each variant is now named for the work it does.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/cert.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/registration.hpp"  // CanonicalSet — the one way a Registry is seated

#include <benchmark/benchmark.h>

#include <blst.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace lux::consensus;

namespace {

constexpr std::uint64_t kStakePer = 1000;

// The consensus vote domain, spelled once for the blst calls that take it raw.
constexpr char kDST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
constexpr std::size_t kDSTLen = sizeof(kDST) - 1;


void be64(std::uint8_t* out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) { out[i] = std::uint8_t(v & 0xFF); v >>= 8; }
}

Id filled(std::uint8_t b) { Id id{}; id.fill(b); return id; }

// The same position every leg signs: every axis non-zero so no field is free.
VotePosition position() {
    VotePosition p{};
    p.chain_id             = filled(0x11);
    p.height               = 0x0102030405060708ULL;
    p.round                = 0x0A0B0C0DU;
    p.block_id             = filled(0x22);
    p.parent_id            = filled(0x33);
    p.canonical_id         = filled(0x44);
    p.parent_canonical_id  = filled(0x55);
    p.execution_state_root = filled(0x66);
    p.payload_root         = filled(0x77);
    p.validator_set_root   = filled(0x88);
    return p;
}

struct Committee {
    VotePosition              pos;
    std::vector<std::uint8_t> msg;
    std::vector<PubKey>       pks;      // ascending, as a cert requires
    std::vector<Signature>    sigs;
    std::vector<std::uint8_t> pks_flat;
    std::vector<std::uint8_t> sigs_flat;
    Signature                 agg{};
    std::array<std::uint8_t, 32> sk0{};
};

// n validators with deterministic keys, their signatures over the canonical
// message, and the aggregate. Keys are re-derived until the compressed pubkeys
// are strictly ascending, because a cert whose voters are unsorted is refused
// before any pairing runs and would time the refusal path.
Committee committee(std::size_t n) {
    Committee c;
    c.pos = position();
    c.msg = canonical_vote_message(c.pos);

    std::vector<std::pair<PubKey, Signature>> pairs;
    pairs.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::array<std::uint8_t, 32> seed{};
        be64(seed.data(), std::uint64_t(i) + 1);
        std::array<std::uint8_t, 32> sk{};
        if (bls::keygen(seed.data(), sk.data()) != 0) throw std::runtime_error("keygen");
        PubKey pk{};
        if (bls::sk_to_pk(sk.data(), pk.data()) != 0) throw std::runtime_error("sk_to_pk");
        Signature sig{};
        if (bls::sign(sk.data(), c.msg.data(), c.msg.size(), sig.data()) != 0)
            throw std::runtime_error("sign");
        if (i == 0) c.sk0 = sk;
        pairs.emplace_back(pk, sig);
    }
    std::sort(pairs.begin(), pairs.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    for (auto& [pk, sig] : pairs) {
        c.pks.push_back(pk);
        c.sigs.push_back(sig);
        c.pks_flat.insert(c.pks_flat.end(), pk.begin(), pk.end());
        c.sigs_flat.insert(c.sigs_flat.end(), sig.begin(), sig.end());
    }
    if (bls::aggregate_sigs(c.sigs_flat.data(), n, c.agg.data()) != 0)
        throw std::runtime_error("aggregate");
    return c;
}

// ── the harness floor ───────────────────────────────────────────────────────
// What one iteration costs when the body does nothing. The nanosecond-scale
// rows are only readable against it — and this build links a google-benchmark
// the distribution compiled without NDEBUG, which the library says so itself on
// every run. This row is how much that warning is worth.
void BM_Empty(benchmark::State& st) {
    std::uint64_t n = 0;
    for (auto _ : st) benchmark::DoNotOptimize(++n);
}
BENCHMARK(BM_Empty);

// ── the canonical message ───────────────────────────────────────────────────
void BM_VoteMessage(benchmark::State& st) {
    const VotePosition p = position();
    for (auto _ : st) benchmark::DoNotOptimize(canonical_vote_message(p));
}
BENCHMARK(BM_VoteMessage);

// ── one signature ───────────────────────────────────────────────────────────
void BM_Sign(benchmark::State& st) {
    const Committee c = committee(1);
    Signature sig{};
    for (auto _ : st) {
        if (bls::sign(c.sk0.data(), c.msg.data(), c.msg.size(), sig.data()) != 0) st.SkipWithError("sign");
        benchmark::DoNotOptimize(sig);
    }
}
BENCHMARK(BM_Sign);

void BM_VerifyOne(benchmark::State& st) {
    const Committee c = committee(1);
    for (auto _ : st) {
        int rc = bls::verify(c.pks[0].data(), c.msg.data(), c.msg.size(), c.sigs[0].data());
        if (rc != 0) st.SkipWithError("verify");
        benchmark::DoNotOptimize(rc);
    }
}
BENCHMARK(BM_VerifyOne);

// ── the portable certificate — the row Go and Rust have a counterpart for ───
// A committee of n, its certificate, and the validator set that resolves the
// voters. Keys are registered once (uncompressed and subgroup-checked there),
// exactly as Go's verifier and Rust's Registry do, so a per-verify figure is
// about the signature being checked and not about a key already trusted.
struct Portable {
    Committee                 c;
    Cert                      cert;
    Registry                  set;
    std::vector<std::uint8_t> wire;
};

Portable portable(std::size_t n) {
    Portable p;
    p.c = committee(n);
    p.cert.version   = kQuorumCertVersion;
    p.cert.role      = kQCFinality;
    p.cert.tier      = Tier::Quasar;
    p.cert.position  = p.c.pos;
    p.cert.threshold = std::uint32_t(n);
    // The committee's set, seated through the admitted set — Registry has no
    // other door, and a benchmark that reached past it would be timing a shape
    // production cannot build. Equal stake, one unit each.
    CanonicalSet admitted;
    admitted.validators.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        Node id{};
        be64(id.data(), std::uint64_t(i) + 1);
        admitted.validators.push_back(CanonicalValidator{id, p.c.pks[i], 1});
        p.cert.votes.push_back(Vote{id, true, std::vector<std::uint8_t>(p.c.sigs[i].begin(), p.c.sigs[i].end())});
    }
    admitted.total_weight = n;
    if (!admitted.install(p.set)) throw std::runtime_error("registry seat");
    p.wire = p.cert.encode();
    // A benchmark of a predicate that refuses measures the refusal path.
    if (p.cert.verify(p.set) != Refusal::None) throw std::runtime_error("committee does not verify");
    return p;
}

void BM_CertVerify(benchmark::State& st) {
    const Portable p = portable(std::size_t(st.range(0)));
    for (auto _ : st) {
        Refusal r = p.cert.verify(p.set);
        if (r != Refusal::None) st.SkipWithError(refusal_name(r));
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_CertVerify)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── the wire, both directions — Rust times the same two ─────────────────────
void BM_CertEncode(benchmark::State& st) {
    const Portable p = portable(std::size_t(st.range(0)));
    for (auto _ : st) benchmark::DoNotOptimize(p.cert.encode());
}
BENCHMARK(BM_CertEncode)->Arg(1)->Arg(21)->Arg(100);

void BM_CertDecode(benchmark::State& st) {
    const Portable p = portable(std::size_t(st.range(0)));
    for (auto _ : st) {
        Refusal why = Refusal::None;
        auto got = Cert::decode(p.wire.data(), p.wire.size(), why);
        if (!got) st.SkipWithError("decode");
        benchmark::DoNotOptimize(got);
    }
}
BENCHMARK(BM_CertDecode)->Arg(1)->Arg(21)->Arg(100);

// ── a finality ROUND ────────────────────────────────────────────────────────
// What the three legs stopped short of. A round is not a predicate; it is the
// work a node does to turn a position into an admitted certificate. Split by
// WHO PAYS, because the three parties pay different amounts:
//
//   sign    one validator's own cost. Builds the canonical message and signs it
//           ONCE. Independent of n — a validator does not sign n times.
//   collect the assembling node: sort the votes into canonical order and encode.
//           O(n), and no curve arithmetic at all.
//   admit   a follower's cost: decode the gossiped bytes and run the predicate.
//           O(n) pairings, and the critical path of finality.
//
// A single "round" number would hide that admit is the only one on the path and
// that sign does not grow with the committee.
void BM_RoundSign(benchmark::State& st) {
    const Committee c = committee(1);
    Signature sig{};
    for (auto _ : st) {
        const std::vector<std::uint8_t> msg = canonical_vote_message(c.pos);
        if (bls::sign(c.sk0.data(), msg.data(), msg.size(), sig.data()) != 0) st.SkipWithError("sign");
        benchmark::DoNotOptimize(sig);
    }
}
BENCHMARK(BM_RoundSign);

void BM_RoundCollect(benchmark::State& st) {
    const Portable p = portable(std::size_t(st.range(0)));
    for (auto _ : st) {
        Cert c = p.cert;
        // Canonical order is the assembler's job: the votes arrive in whatever
        // order they were gossiped, and the certificate's bytes are the sorted
        // ones. Reversing first makes the sort do work rather than confirm it.
        std::reverse(c.votes.begin(), c.votes.end());
        std::sort(c.votes.begin(), c.votes.end(),
                  [](const Vote& a, const Vote& b) { return a.node < b.node; });
        benchmark::DoNotOptimize(c.encode());
    }
}
BENCHMARK(BM_RoundCollect)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

void BM_RoundAdmit(benchmark::State& st) {
    const Portable p = portable(std::size_t(st.range(0)));
    for (auto _ : st) {
        Refusal why = Refusal::None;
        auto got = Cert::decode(p.wire.data(), p.wire.size(), why);
        if (!got) { st.SkipWithError("decode"); break; }
        Refusal r = got->verify(p.set);
        if (r != Refusal::None) { st.SkipWithError(refusal_name(r)); break; }
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_RoundAdmit)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── aggregation, by the work it does ────────────────────────────────────────
// AggregateFromCompressed is what bls::aggregate_sigs offers: n compressed
// signatures in, one out, so it pays an uncompress and a subgroup check per
// signature. AggregateFromPoints is the sum alone, over points already
// decompressed and already checked. The gap between them is not a language
// difference; it is what the caller was asked to hand in.
void BM_AggregateFromCompressed(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    Signature agg{};
    for (auto _ : st) {
        if (bls::aggregate_sigs(c.sigs_flat.data(), n, agg.data()) != 0) st.SkipWithError("aggregate");
        benchmark::DoNotOptimize(agg);
    }
}
BENCHMARK(BM_AggregateFromCompressed)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

void BM_AggregateFromPoints(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    std::vector<blst_p2_affine> pts(n);
    for (std::size_t i = 0; i < n; ++i)
        if (blst_p2_uncompress(&pts[i], c.sigs[i].data()) != BLST_SUCCESS)
            throw std::runtime_error("uncompress");
    for (auto _ : st) {
        blst_p2 acc{};
        blst_p2_from_affine(&acc, &pts[0]);
        for (std::size_t i = 1; i < n; ++i) blst_p2_add_or_double_affine(&acc, &acc, &pts[i]);
        benchmark::DoNotOptimize(acc);
    }
}
BENCHMARK(BM_AggregateFromPoints)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── the O(1) predicate — sum the keys, one pairing ──────────────────────────
// FromCompressed decompresses and subgroup-checks all n keys on every call.
// FromPoints starts from keys a validator set already holds decompressed, which
// is what Go's leg is handed. Both are here so the row that is compared is the
// row that does the same work.
void BM_FastAggVerifyFromCompressed(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    for (auto _ : st) {
        int rc = bls::fast_aggregate_verify(c.pks_flat.data(), n,
                                                  c.msg.data(), c.msg.size(), c.agg.data());
        if (rc != 0) st.SkipWithError("fast_aggregate_verify");
        benchmark::DoNotOptimize(rc);
    }
}
BENCHMARK(BM_FastAggVerifyFromCompressed)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

void BM_FastAggVerifyFromPoints(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    std::vector<blst_p1_affine> keys(n);
    for (std::size_t i = 0; i < n; ++i)
        if (blst_p1_uncompress(&keys[i], c.pks[i].data()) != BLST_SUCCESS)
            throw std::runtime_error("uncompress pk");
    blst_p2_affine agg{};
    if (blst_p2_uncompress(&agg, c.agg.data()) != BLST_SUCCESS) throw std::runtime_error("uncompress agg");

    for (auto _ : st) {
        blst_p1 acc{};
        blst_p1_from_affine(&acc, &keys[0]);
        for (std::size_t i = 1; i < n; ++i) blst_p1_add_or_double_affine(&acc, &acc, &keys[i]);
        blst_p1_affine sum{};
        blst_p1_to_affine(&sum, &acc);
        // bls::pair, not blst_core_verify_pk_in_g1 — the Go and Rust legs reach
        // this row through their bindings' pairing, so reaching it through the
        // other entry point would put an 8% entry-point difference into a row
        // about summing public keys.
        const bool ok = bls::pair(sum, agg, c.msg.data(), c.msg.size());
        if (!ok) st.SkipWithError("aggregate pairing");
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_FastAggVerifyFromPoints)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── the shipped gate, whole ─────────────────────────────────────────────────
// QuorumCertEngine::verify_cert: the structural clauses, the recomputed stake and
// count floors, and the O(1) aggregate pairing. The certificate carries the whole
// committee, so it clears both floors and the pairing is what is being timed.
void BM_EngineVerifyCert(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);

    std::vector<Validator> set;
    set.reserve(n);
    for (const auto& pk : c.pks) set.push_back(Validator{pk, kStakePer});
    QuorumCertEngine engine(set);

    QuorumCert cert{};
    cert.version       = kQuorumCertVersion;
    cert.type          = kQCFinality;
    cert.tier          = Tier::Quasar;
    cert.position      = c.pos;
    // The engine derives the export floor from the set, and verify_cert refuses a
    // certificate whose declared threshold is not that number — so read it off the
    // engine rather than restating it here.
    cert.threshold     = engine.signer_floor(Tier::Quasar);
    cert.voters        = c.pks;
    cert.aggregate_sig = c.agg;
    cert.voted_stake   = kStakePer * n;
    cert.total_stake   = kStakePer * n;

    if (!engine.verify_cert(cert)) { st.SkipWithError("cert does not verify"); return; }
    for (auto _ : st) {
        bool ok = engine.verify_cert(cert);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_EngineVerifyCert)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);


// ── decomposition: where a verify actually spends its time ──────────────────
// The three legs do DIFFERENT work per verification, so the single-verify
// figures are not comparable until the difference is priced. These break
// bls::verify into its parts:
//
//   Go's benchRegistry per verify : P2 uncompress, in_g2 (twice — SigValidate
//                                   and again as sigGroupcheck), core_verify.
//                                   The public key is cached DECOMPRESSED and
//                                   pkValidate is off.
//   C++ bls::verify per verify    : P1 uncompress, in_g1, P2 uncompress, in_g2,
//                                   core_verify.
//
// BM_VerifyMatchedToGo runs the C++ side of that comparison on Go's terms.

void BM_UncompressPK(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    for (auto _ : st) {
        BLST_ERROR e = blst_p1_uncompress(&pk, c.pks[0].data());
        benchmark::DoNotOptimize(e);
        benchmark::DoNotOptimize(pk);
    }
}
BENCHMARK(BM_UncompressPK);

void BM_InG1(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    blst_p1_uncompress(&pk, c.pks[0].data());
    for (auto _ : st) {
        bool ok = blst_p1_affine_in_g1(&pk);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_InG1);

void BM_UncompressSig(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p2_affine sig{};
    for (auto _ : st) {
        BLST_ERROR e = blst_p2_uncompress(&sig, c.sigs[0].data());
        benchmark::DoNotOptimize(e);
        benchmark::DoNotOptimize(sig);
    }
}
BENCHMARK(BM_UncompressSig);

void BM_InG2(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p2_affine sig{};
    blst_p2_uncompress(&sig, c.sigs[0].data());
    for (auto _ : st) {
        bool ok = blst_p2_affine_in_g2(&sig);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_InG2);

// THE PAIRING, TWO WAYS. blst offers two entry points for one signature, and
// which one a binding picks is worth 8% of every verification:
//
//   PairDirect    blst_core_verify_pk_in_g1 — both points in one generic
//                 multi-Miller loop. What this leg used to call.
//   PairFixedGen  accumulate e(pk, H(m)), then pair the signature against the
//                 FIXED generator with blst_aggregated_in_g2. What the Go and
//                 Rust bindings call, and what bls::pair now calls.
//
// Both are timed so the choice stays visible: it is the reason the C++ figure
// once looked like a language difference, and a future rewrite that quietly
// goes back to the direct call will show up here.
void BM_CoreVerifyOnly(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    blst_p2_affine sig{};
    blst_p1_uncompress(&pk, c.pks[0].data());
    blst_p2_uncompress(&sig, c.sigs[0].data());
    for (auto _ : st) {
        BLST_ERROR e = blst_core_verify_pk_in_g1(&pk, &sig, true,
                                                 c.msg.data(), c.msg.size(),
                                                 reinterpret_cast<const std::uint8_t*>(kDST),
                                                 kDSTLen, nullptr, 0);
        benchmark::DoNotOptimize(e);
    }
}
BENCHMARK(BM_CoreVerifyOnly);

void BM_PairFixedGen(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    blst_p2_affine sig{};
    blst_p1_uncompress(&pk, c.pks[0].data());
    blst_p2_uncompress(&sig, c.sigs[0].data());
    for (auto _ : st) benchmark::DoNotOptimize(bls::pair(pk, sig, c.msg.data(), c.msg.size()));
}
BENCHMARK(BM_PairFixedGen);

// C++ on the other legs' terms: public key cached decompressed and unvalidated,
// signature decompressed and group-checked per call, then the pairing THEY
// call. This is the figure comparable to Go's VerifyMatched and Rust's
// matched/verify — the same blst calls in the same order.
void BM_VerifyMatched(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    blst_p1_uncompress(&pk, c.pks[0].data());
    for (auto _ : st) {
        blst_p2_affine sig{};
        BLST_ERROR e = blst_p2_uncompress(&sig, c.sigs[0].data());
        bool grp = blst_p2_affine_in_g2(&sig);
        bool v = bls::pair(pk, sig, c.msg.data(), c.msg.size());
        benchmark::DoNotOptimize(e);
        benchmark::DoNotOptimize(grp);
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_VerifyMatched);

}  // namespace

BENCHMARK_MAIN();
