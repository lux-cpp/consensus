// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// fpc_conformance_test.cpp — the adaptive threshold against the SHARED corpus.
//
// conformance_test.cpp reads this repo's own vectors/. This reads
// luxfi/conformance, the one corpus the Go node, the Rust crates and this C++
// answer to. Nothing here states what an answer ought to be; the corpus does,
// and the corpus is regenerated from Go.
//
// α is the count of votes a round accepts on. Everything else in consensus can
// be right while this is wrong and the network still forks, because two nodes
// that derive different thresholds from the same committee are not running one
// protocol. So this checks the whole chain of it, at every joint the two
// languages could part company:
//
//   the preimage bytes   — before any hash, so a disagreement names a byte
//                          string instead of an opaque digest
//   the seed             — sha256 of those bytes
//   the PRF digest       — sha256(seed ‖ be64(phase)), the θ input
//   θ                    — as exact IEEE-754 bits, because α is a ceiling and
//                          the last bit decides
//   α                    — the number a round is actually decided by
//
// and the negative pairs: two triples the encoding must keep apart. Every
// positive case here still passes under a preimage written end to end, because
// inside one case no length varies. The pairs are what catch a port that
// dropped the length prefixes and looks green.

#include "lux/consensus/fpc.hpp"
#include "lux/consensus/threshold.hpp"

#include "json.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

using namespace lux::consensus;

namespace {

int g_pass = 0, g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("    FAIL: %s\n", what.c_str());
}

[[noreturn]] void die(const std::string& why) {
    std::printf("fpc conformance: %s\n", why.c_str());
    std::exit(2);
}

void banner(const char* what) { std::printf("\n-- %s\n", what); }

// The corpus directory: $LUX_VECTORS when set, otherwise the path the build was
// configured with. Same order the Rust harness uses, so one environment points
// every language at one corpus.
std::string corpus_dir() {
    if (const char* env = std::getenv("LUX_VECTORS")) return env;
    return LUX_CORPUS;
}

json::Value load(const std::string& name) {
    const std::string path = corpus_dir() + "/" + name;
    std::ifstream in(path, std::ios::binary);
    if (!in)
        die("cannot open " + path +
            "\n  this harness reads the luxfi/conformance corpus, not this repo's vectors/."
            "\n  point it at one with LUX_VECTORS=/path/to/conformance/vectors, or configure"
            "\n  the build with -DLUX_CORPUS_DIR=/path/to/conformance/vectors.");
    std::ostringstream buf;
    buf << in.rdbuf();
    return json::parse(buf.str());
}

std::vector<std::uint8_t> unhex(const std::string& h) {
    if (h.size() % 2) die("odd-length hex in corpus: " + h);
    std::vector<std::uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        const std::string byte = h.substr(i, 2);
        out.push_back(static_cast<std::uint8_t>(std::strtoul(byte.c_str(), nullptr, 16)));
    }
    return out;
}

std::string hex(std::span<const std::uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (const std::uint8_t x : b) {
        out.push_back(d[x >> 4]);
        out.push_back(d[x & 0xF]);
    }
    return out;
}

// A double as the corpus records it: the IEEE-754 bit pattern, big-endian hex.
// Decimal text is a rendering — two implementations can print the same digits
// and hold different numbers, and α is a ceiling, so the difference lands on a
// vote count.
std::string bits(double d) {
    std::uint64_t u = 0;
    std::memcpy(&u, &d, sizeof u);
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%016llx", static_cast<unsigned long long>(u));
    return buf;
}

// ── 1. the epoch seed: the bytes, the digest, and the α that follows ─────────
void epoch_seed_plane() {
    banner("epoch seed — fpc.EpochSeedPreimage / DeriveEpochSeed (fpc_epoch_seed.json)");
    const json::Value v = load("fpc_epoch_seed.json");

    const std::string domain = v.at("domain").text();
    check(domain == std::string(fpc::kSeedDomain),
          "the corpus takes the seed under domain \"" + domain + "\", this build uses \"" +
              std::string(fpc::kSeedDomain) + "\"");

    const json::Value& cases = v.at("cases");
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const json::Value& c = cases[i];
        const std::string where = "case " + std::to_string(i) + " (" + c.at("note").text() + ")";

        const std::uint64_t epoch = c.at("epoch").u64();
        const std::vector<std::uint8_t> chain = unhex(c.at("chain_id").text());
        const std::vector<std::uint8_t> parent = unhex(c.at("prev_block_hash").text());

        const std::vector<std::uint8_t> pre = fpc::seed_preimage(epoch, chain, parent);
        const std::string want_pre = c.at("preimage").text();
        check(hex(pre) == want_pre,
              where + ": the preimage differs — go " + want_pre + " cpp " + hex(pre));
        check(pre.size() == c.at("preimage_len").u64(),
              where + ": preimage length " + std::to_string(pre.size()) + ", corpus says " +
                  c.at("preimage_len").text());

        const std::array<std::uint8_t, 32> seed = fpc::epoch_seed(epoch, chain, parent);
        const std::string want_seed = c.at("seed").text();
        check(hex(seed) == want_seed,
              where + ": the seed differs — go " + want_seed + " cpp " + hex(seed));

        // α at k=20 phase 1, which is what the seed is for.
        const std::optional<int> a = fpc::alpha(seed, 1, 20);
        const auto want_alpha = static_cast<int>(c.at("alpha_k20_phase1").u64());
        check(a.has_value() && *a == want_alpha,
              where + ": k=20 phase 1 — go accepts on " + std::to_string(want_alpha) +
                  " votes, cpp on " + (a ? std::to_string(*a) : std::string("nothing")));
    }
    std::printf("    %zu cases\n", cases.size());
}

// ── 2. the pairs the encoding must keep apart ────────────────────────────────
void separation_plane() {
    banner("epoch seed — the triples a concatenated preimage would merge");
    const json::Value v = load("fpc_epoch_seed.json");
    const json::Value& pairs = v.at("must_not_collide");
    check(pairs.size() > 0, "the corpus carries no separation pairs");

    for (std::size_t i = 0; i < pairs.size(); ++i) {
        const json::Value& p = pairs[i];
        const std::string where = "pair " + std::to_string(i);
        check(!p.at("seeds_are_equal").boolean(),
              where + ": the corpus records as separated a pair Go merged");

        const std::uint64_t epoch = p.at("epoch").u64();
        const std::array<std::uint8_t, 32> left = fpc::epoch_seed(
            epoch, unhex(p.at("left_chain_id").text()), unhex(p.at("left_prev_block_hash").text()));
        const std::array<std::uint8_t, 32> right =
            fpc::epoch_seed(epoch, unhex(p.at("right_chain_id").text()),
                            unhex(p.at("right_prev_block_hash").text()));

        check(hex(left) == p.at("left_seed").text(), where + ": left seed differs from Go");
        check(hex(right) == p.at("right_seed").text(), where + ": right seed differs from Go");
        check(left != right,
              where + ": this build merges two triples the network separates — " +
                  p.at("note").text() + "; both reach " + hex(left));
    }
    std::printf("    %zu pairs\n", pairs.size());
}

// ── 3. θ and α across the phases ─────────────────────────────────────────────
void theta_plane() {
    banner("theta — fpc.Selector.Theta / SelectThreshold (fpc_theta.json)");
    const json::Value v = load("fpc_theta.json");

    const std::vector<std::uint8_t> seed = unhex(v.at("seed_hex").text());
    const double tmin = std::stod(v.at("theta_min").text());
    const double tmax = std::stod(v.at("theta_max").text());

    const json::Value& cases = v.at("cases");
    std::size_t alphas = 0;
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const json::Value& c = cases[i];
        const std::uint64_t phase = c.at("phase").u64();
        const std::string where = "phase " + std::to_string(phase);

        const std::optional<std::array<std::uint8_t, 32>> digest = fpc::theta_digest(seed, phase);
        check(digest.has_value() && hex(*digest) == c.at("digest").text(),
              where + ": the PRF digest differs — the two languages hash different bytes; go " +
                  c.at("digest").text() + " cpp " + (digest ? hex(*digest) : std::string("none")));

        const std::optional<double> t = fpc::theta(seed, phase, tmin, tmax);
        check(t.has_value() && bits(*t) == c.at("theta_bits").text(),
              where + ": theta differs — go " + c.at("theta_bits").text() + " (" +
                  c.at("theta").text() + ") cpp " + (t ? bits(*t) : std::string("none")));

        const json::Value& alpha_by_k = c.at("alpha");
        for (const std::string& k_text : alpha_by_k.keys()) {
            const auto k = static_cast<std::uint32_t>(std::stoul(k_text));
            const auto want = static_cast<int>(alpha_by_k.at(k_text).u64());
            const std::optional<int> got = fpc::alpha(seed, phase, k, tmin, tmax);
            check(got.has_value() && *got == want,
                  where + ", k=" + k_text + ": go accepts on " + std::to_string(want) +
                      " votes, cpp on " + (got ? std::to_string(*got) : std::string("nothing")));
            ++alphas;
        }
    }
    std::printf("    %zu phases, %zu thresholds\n", cases.size(), alphas);
}

// ── 4. refusal, which is part of the definition ──────────────────────────────
void refusal_plane() {
    banner("refusal — an empty seed is not a threshold");
    // Go's NewSelector returns ErrEmptySeed. A port that hashes nothing and
    // returns 0.5·k has answered a question it was not asked, and the answer
    // looks exactly like a threshold.
    const std::span<const std::uint8_t> empty{};
    check(!fpc::theta(empty, 0).has_value(), "theta accepted an empty seed");
    check(!fpc::alpha(empty, 0, 20).has_value(), "alpha accepted an empty seed");
    check(!fpc::theta_digest(empty, 0).has_value(), "theta_digest accepted an empty seed");

    // The genesis epoch is a real value, not an absent one: a driver told no
    // epoch derives it, and every node derives the same one.
    const std::span<const std::uint8_t> none{};
    const std::array<std::uint8_t, 32> genesis = fpc::epoch_seed(0, none, none);
    check(fpc::alpha(genesis, 0, 20).has_value(), "the genesis seed is not usable");
}

}  // namespace

int main() {
    std::printf("fpc conformance — the adaptive threshold against the Go corpus\n");
    std::printf("corpus: %s\n", corpus_dir().c_str());
    try {
        epoch_seed_plane();
        separation_plane();
        theta_plane();
        refusal_plane();
    } catch (const std::exception& e) {
        die(e.what());
    }
    std::printf("\n%d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
