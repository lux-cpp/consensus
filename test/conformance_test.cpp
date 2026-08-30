// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// conformance_test.cpp — consensus against the Go corpus.
//
// Go is the source of truth. scripts/oracle reads the values out of the running
// Go implementation and writes them here; this harness re-derives each one in
// C++ and demands byte equality. Nothing in this file states what the answer
// ought to be — the corpus does, and the corpus is regenerable.
//
// Four things are pinned, and they are exactly the four that were found to have
// silently drifted:
//   1. THE SIGNED MESSAGE — chain.CanonicalVoteMessage, 226 bytes, every axis.
//   2. THE DOMAIN TAG    — a signature is a hash-to-curve under a DST. Same key,
//                          same message, wrong tag ⇒ a signature the other side
//                          rejects. Pinned by pinning bls.Sign's output.
//   3. THE STAKE FLOORS  — config.TwoThirdsStakeFloor / HalfStakeFloor, to
//                          MaxUint64.
//   4. THE COMMITTEE     — NovaQuorum, NovaSignerFloor,
//                          EqualStakeSupermajorityThreshold, AlphaForK (ceil).

#include "lux/consensus/bls.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/threshold.hpp"
#include "lux/consensus/wave.hpp"

#include "bls_signature.hpp"  // the eth2 POP surface — the domain trap, proven below

#include "json.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace lux::consensus;

namespace {

int g_pass = 0, g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; return; }
    ++g_fail;
    std::printf("    FAIL: %s\n", what.c_str());
}

[[noreturn]] void die(const std::string& why) {
    std::printf("conformance: %s\n", why.c_str());
    std::exit(2);
}

// ── the corpus reader ────────────────────────────────────────────────────────
// The parser is json.hpp, shared with fpc_conformance_test: two readers would
// be two opinions about what the same bytes say.
//
// The SCHEMA is this file's, and it stays strict. This corpus is an ARRAY of
// FLAT objects whose values are strings, numbers or booleans — that is all of
// it, and anything nested is a corpus that does not match its schema, which is
// an error rather than something to skip past. Values are kept as their literal
// text: a uint64 near MaxUint64 must not go through a double, and the stake
// floors sit there deliberately.
using Row = std::map<std::string, std::string>;

std::vector<Row> load(const std::string& name) {
    const std::string path = std::string(CONSENSUS_VECTORS) + "/" + name;
    std::ifstream in(path, std::ios::binary);
    if (!in) die("cannot open " + path + " (regenerate: go run ./scripts/oracle -out vectors)");
    std::ostringstream buf;
    buf << in.rdbuf();

    json::Value top;
    try {
        top = json::parse(buf.str());
    } catch (const std::exception& e) {
        die(std::string("parse ") + name + ": " + e.what());
    }
    if (!top.is_array()) die(name + ": the corpus is an array of rows by schema");

    std::vector<Row> rows;
    rows.reserve(top.size());
    for (std::size_t i = 0; i < top.size(); ++i) {
        const json::Value& obj = top[i];
        if (!obj.is_object()) die(name + ": a corpus row is an object by schema");
        Row row;
        const std::vector<std::string>& keys = obj.keys();
        for (std::size_t k = 0; k < keys.size(); ++k) {
            const json::Value& v = obj.items()[k];
            if (v.is_object() || v.is_array())
                die(name + ": corpus objects are FLAT by schema: " + keys[k]);
            row[keys[k]] = v.text();
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

const std::string& field(const Row& r, const std::string& key) {
    const auto it = r.find(key);
    if (it == r.end()) die("corpus row is missing field " + key);
    return it->second;
}

std::uint64_t u64(const Row& r, const std::string& key) {
    return std::strtoull(field(r, key).c_str(), nullptr, 10);
}

std::vector<std::uint8_t> unhex(const std::string& h) {
    if (h.size() % 2) die("odd-length hex in corpus");
    std::vector<std::uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::strtoul(h.substr(i, 2).c_str(), nullptr, 16)));
    return out;
}

std::string hex(const std::uint8_t* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { out.push_back(d[b[i] >> 4]); out.push_back(d[b[i] & 0xF]); }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(const Row& r, const std::string& key) {
    const std::vector<std::uint8_t> v = unhex(field(r, key));
    if (v.size() != N) die("corpus field " + key + " has the wrong width");
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = v[i];
    return out;
}

void banner(const char* what) { std::printf("\n-- %s\n", what); }

// ── 1. the signed vote message ───────────────────────────────────────────────
void vote_message() {
    banner("vote message — chain.CanonicalVoteMessage (226 bytes, every axis bound)");
    for (const Row& r : load("vote_message.json")) {
        const std::string name = field(r, "name");
        check(u64(r, "version") == kQuorumCertVersion, name + ": cert version matches Go");
        check(u64(r, "qc_type") == kQCFinality, name + ": qc type matches Go");

        VotePosition pos;
        pos.chain_id             = fixed<32>(r, "chain_id");
        pos.height               = u64(r, "height");
        pos.round                = static_cast<std::uint32_t>(u64(r, "round"));
        pos.block_id             = fixed<32>(r, "block_id");
        pos.parent_id            = fixed<32>(r, "parent_id");
        pos.canonical_id         = fixed<32>(r, "canonical_id");
        pos.parent_canonical_id  = fixed<32>(r, "parent_canonical_id");
        pos.execution_state_root = fixed<32>(r, "execution_state_root");
        pos.payload_root         = fixed<32>(r, "payload_root");
        pos.validator_set_root   = fixed<32>(r, "validator_set_root");

        const bool accept = field(r, "accept") == "true";
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, accept);
        check(msg.size() == 226, name + ": message is 226 bytes");
        check(hex(msg.data(), msg.size()) == field(r, "message"),
              name + ": message bytes are Go's, exactly");

        // The REJECT message must differ from the ACCEPT one in the last byte and
        // nowhere else: a reject signature can never be presented as an accept.
        const std::vector<std::uint8_t> other = canonical_vote_message(pos, !accept);
        check(other.size() == msg.size() && other.back() != msg.back() &&
                  std::equal(msg.begin(), msg.end() - 1, other.begin()),
              name + ": the accept byte, and only it, separates accept from reject");
    }
}

// ── 2. the domain separation tag ─────────────────────────────────────────────
void vote_signature() {
    banner("vote signature — the domain tag (bls.Sign, ..._RO_NUL_)");
    check(std::string(bls::kVoteDST) == "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
          "the consensus vote DST is Go's dstSignature");

    for (const Row& r : load("vote_signature.json")) {
        const std::string name = field(r, "name");
        const auto sk  = fixed<32>(r, "sk");
        const auto pk  = fixed<48>(r, "pk");
        const auto msg = unhex(field(r, "message"));

        std::array<std::uint8_t, 48> derived{};
        check(bls::sk_to_pk(sk.data(), derived.data()) == 0 && derived == pk,
              name + ": public key derives from the secret key as Go's does");

        std::array<std::uint8_t, 96> sig{};
        check(bls::sign(sk.data(), msg.data(), msg.size(), sig.data()) == 0,
              name + ": sign succeeds");
        check(hex(sig.data(), sig.size()) == field(r, "sig"),
              name + ": signature is byte-identical to Go's — the tag agrees");
        check(bls::verify(pk.data(), msg.data(), msg.size(), sig.data()) == 0,
              name + ": our verify accepts Go's signature");

        // THE TRAP, proven: the reused eth2 surface signs the SAME key over the SAME
        // message under ..._RO_POP_. It produces a different signature, and the two
        // domains reject each other. This is why consensus has its own surface.
        std::array<std::uint8_t, 96> pop{};
        check(cevm::crypto::bls::sign(sk.data(), msg.data(), msg.size(), pop.data()) == 0,
              name + ": the eth2 POP surface signs too");
        check(pop != sig, name + ": a POP-domain signature is NOT the consensus one");
        check(bls::verify(pk.data(), msg.data(), msg.size(), pop.data()) != 0,
              name + ": the consensus domain rejects a POP-domain signature");
    }
}

// ── 3. the stake floors ──────────────────────────────────────────────────────
void stake_floor() {
    banner("stake floors — config.TwoThirdsStakeFloor / HalfStakeFloor (to MaxUint64)");
    std::size_t n = 0;
    for (const Row& r : load("stake_floor.json")) {
        const std::uint64_t total = u64(r, "total");
        check(two_thirds_stake_floor(total) == u64(r, "two_thirds_floor"),
              "two_thirds_stake_floor(" + field(r, "total") + ")");
        check(half_stake_floor(total) == u64(r, "half_floor"),
              "half_stake_floor(" + field(r, "total") + ")");
        ++n;
    }
    std::printf("   %zu totals compared\n", n);
}

// ── 4. the committee thresholds ──────────────────────────────────────────────
void committee() {
    banner("committee — NovaQuorum / NovaSignerFloor / EqualStakeSupermajority / AlphaForK");
    for (const Row& r : load("committee.json")) {
        const auto n = static_cast<std::uint32_t>(u64(r, "n"));
        const std::string at = "(n=" + field(r, "n") + ")";
        check(nova_quorum(n) == u64(r, "nova_quorum"), "nova_quorum" + at);
        check(nova_signer_floor(n) == u64(r, "nova_signer_floor"), "nova_signer_floor" + at);
        check(equal_stake_supermajority(n) == u64(r, "equal_stake_supermajority"),
              "equal_stake_supermajority" + at);
        // The truncation bug lived exactly here: trunc(21·0.69)=14 where Go
        // declares 15. ceil, and only ceil, reproduces the corpus.
        check(static_cast<std::uint64_t>(alpha_threshold(n, kConsensusSuperMajority)) ==
                  u64(r, "alpha_for_k"),
              "alpha_threshold" + at + " == Go AlphaForK (ceil, not truncation)");
    }
    // The wave a live set of n runs must agree with the same rule — at EVERY
    // size, not a five-point sample. This loop used to check {4,5,11,21,100},
    // and the ratio it checked round-tripped correctly for exactly those five
    // while overshooting by one for 33 other sizes in 4..1000. n=41 asked for
    // 29 where Go's quorum is 28, so a round sitting at 28/41 never decided,
    // and no test here could see it. A sample cannot establish "matches Go at
    // every committee size"; the sweep can.
    {
        std::uint32_t diverged = 0, first = 0;
        for (std::uint32_t n = 4; n <= 1000; ++n) {
            const WaveConfig cfg = WaveConfig::feasible(n);
            if (cfg.k != n || cfg.threshold != equal_stake_supermajority(n)) {
                if (diverged == 0) first = n;
                ++diverged;
            }
        }
        check(diverged == 0,
              diverged == 0
                  ? std::string("feasible(n) is the strict-⅔ count for every n in 4..1000")
                  : "feasible(n) diverges at " + std::to_string(diverged) +
                        " sizes, first n=" + std::to_string(first));
    }
    // The size the ratio got wrong, named, so a regression is legible.
    check(WaveConfig::feasible(41).threshold == 28,
          "feasible(41) quorum is 28 — the size the float representation missed");
}

}  // namespace

int main() {
    std::printf("================== consensus — GO CONFORMANCE ==================\n");
    std::printf("corpus: %s\n", CONSENSUS_VECTORS);

    vote_message();
    vote_signature();
    stake_floor();
    committee();

    std::printf("\n----------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== GO CONFORMANCE: FAIL ====\n"); return 1; }
    std::printf("==== GO CONFORMANCE: PASS — message, domain, floors, committee ====\n");
    return 0;
}
