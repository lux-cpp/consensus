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
// TWO CERTIFICATE PREDICATES ARE TIMED, deliberately:
//
//   cert_verify_persig  — one pairing PER VOTE, the loop Go's QuorumCert.Verify
//                         and Rust's Cert::verify run. Written here so the C++
//                         number has a counterpart that does the same work.
//   verify_cert         — QuorumCertEngine::verify_cert, the shipped C++ gate:
//                         sum the n public keys, ONE aggregate pairing.
//
// These are different algorithms at the same n. Reporting only the second beside
// the other languages' first would report the algorithm as a language result.

#include "lux/consensus/bls.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"

#include <benchmark/benchmark.h>

#include <blst.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace lux::consensus;

namespace {

constexpr std::uint64_t kStakePer = 1000;

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

// ── the O(n) predicate — what Go and Rust run ───────────────────────────────
void BM_CertVerifyPerSig(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    for (auto _ : st) {
        bool ok = true;
        for (std::size_t i = 0; i < n; ++i) {
            if (i > 0 && !(c.pks[i - 1] < c.pks[i])) { ok = false; break; }
            if (bls::verify(c.pks[i].data(), c.msg.data(), c.msg.size(), c.sigs[i].data()) != 0) {
                ok = false;
                break;
            }
        }
        if (!ok) st.SkipWithError("per-sig verify");
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_CertVerifyPerSig)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── aggregation ─────────────────────────────────────────────────────────────
void BM_Aggregate(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    Signature agg{};
    for (auto _ : st) {
        if (bls::aggregate_sigs(c.sigs_flat.data(), n, agg.data()) != 0) st.SkipWithError("aggregate");
        benchmark::DoNotOptimize(agg);
    }
}
BENCHMARK(BM_Aggregate)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── the O(1) predicate — sum the keys, one pairing ──────────────────────────
void BM_FastAggVerify(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);
    for (auto _ : st) {
        int rc = bls::fast_aggregate_verify(c.pks_flat.data(), n,
                                                  c.msg.data(), c.msg.size(), c.agg.data());
        if (rc != 0) st.SkipWithError("fast_aggregate_verify");
        benchmark::DoNotOptimize(rc);
    }
}
BENCHMARK(BM_FastAggVerify)->Arg(1)->Arg(4)->Arg(21)->Arg(41)->Arg(100);

// ── the shipped gate, whole ─────────────────────────────────────────────────
// QuorumCertEngine::verify_cert: the structural clauses, the recomputed stake
// floor, and the O(1) aggregate pairing. The engine is built with alpha equal to
// the committee size so the cert this builds clears its own floor.
void BM_EngineVerifyCert(benchmark::State& st) {
    const std::size_t n = std::size_t(st.range(0));
    const Committee c = committee(n);

    std::vector<Validator> set;
    set.reserve(n);
    for (const auto& pk : c.pks) set.push_back(Validator{pk, kStakePer});
    QuorumCertEngine engine(set, std::uint32_t(n));

    QuorumCert cert{};
    cert.version       = kQuorumCertVersion;
    cert.type          = kQCFinality;
    cert.tier          = Tier::Quasar;
    cert.position      = c.pos;
    cert.threshold     = std::uint32_t(n);
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

constexpr char kDST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
constexpr std::size_t kDSTLen = sizeof(kDST) - 1;

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

// The pairing itself: hash-to-curve + two Miller loops + final exponentiation,
// with both points already decompressed and both group checks already paid.
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

// C++ on Go's terms: public key cached decompressed and unvalidated, signature
// decompressed and group-checked per call, then the pairing. This is the figure
// that is comparable to the Go leg's VerifyOne.
void BM_VerifyMatchedToGo(benchmark::State& st) {
    const Committee c = committee(1);
    blst_p1_affine pk{};
    blst_p1_uncompress(&pk, c.pks[0].data());
    for (auto _ : st) {
        blst_p2_affine sig{};
        BLST_ERROR e = blst_p2_uncompress(&sig, c.sigs[0].data());
        bool grp = blst_p2_affine_in_g2(&sig);
        BLST_ERROR v = blst_core_verify_pk_in_g1(&pk, &sig, true,
                                                 c.msg.data(), c.msg.size(),
                                                 reinterpret_cast<const std::uint8_t*>(kDST),
                                                 kDSTLen, nullptr, 0);
        benchmark::DoNotOptimize(e);
        benchmark::DoNotOptimize(grp);
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_VerifyMatchedToGo);

}  // namespace

BENCHMARK_MAIN();
