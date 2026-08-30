// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// fpc.cpp — the adaptive threshold. See fpc.hpp for which Go definition each
// function mirrors.
//
// Two things here are load-bearing and easy to lose:
//
// SHA-256 is blst's. blst exports blst_sha256 (src/exports.c) but its public
// header does not declare it, so the declaration is here. It is the same
// implementation the curve code hashes with, already linked into this tree —
// a second SHA-256 beside it would be a second answer to a question that has
// one.
//
// The float arithmetic is written to be reproduced, not to be fast. θ is a
// double and α is a ceiling of it, so the last bit of θ decides whether a round
// accepts on 15 votes or 16. Contracting `min + n·(max−min)` into an FMA would
// make this file MORE accurate than Go and therefore wrong: it would compute a
// different α from the same seed. The build turns contraction off; the
// conformance test compares θ as exact IEEE-754 bits, so if it ever comes back
// the harness says so rather than the network finding out.

#include "lux/consensus/fpc.hpp"

#include "lux/consensus/threshold.hpp"

#include <cstddef>
#include <cstring>

// blst's SHA-256. Declared here because blst.h does not declare it; the symbol
// is public in the static library this target already links.
extern "C" void blst_sha256(unsigned char md[32], const void* msg, std::size_t len);

namespace lux::consensus::fpc {
namespace {

void put_be64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFF));
}

std::uint64_t be64(const std::uint8_t* b) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}

}  // namespace

std::vector<std::uint8_t> seed_preimage(std::uint64_t epoch,
                                        std::span<const std::uint8_t> chain,
                                        std::span<const std::uint8_t> parent) {
    std::vector<std::uint8_t> out;
    out.reserve(kSeedDomain.size() + 24 + chain.size() + parent.size());
    out.insert(out.end(), kSeedDomain.begin(), kSeedDomain.end());
    put_be64(out, epoch);
    put_be64(out, chain.size());
    out.insert(out.end(), chain.begin(), chain.end());
    put_be64(out, parent.size());
    out.insert(out.end(), parent.begin(), parent.end());
    return out;
}

std::array<std::uint8_t, 32> epoch_seed(std::uint64_t epoch,
                                        std::span<const std::uint8_t> chain,
                                        std::span<const std::uint8_t> parent) {
    const std::vector<std::uint8_t> pre = seed_preimage(epoch, chain, parent);
    std::array<std::uint8_t, 32> out{};
    blst_sha256(out.data(), pre.data(), pre.size());
    return out;
}

std::optional<std::array<std::uint8_t, 32>> theta_digest(std::span<const std::uint8_t> seed,
                                                         std::uint64_t phase) {
    if (seed.empty()) return std::nullopt;  // Go: ErrEmptySeed
    std::vector<std::uint8_t> pre;
    pre.reserve(seed.size() + 8);
    pre.insert(pre.end(), seed.begin(), seed.end());
    put_be64(pre, phase);

    std::array<std::uint8_t, 32> digest{};
    blst_sha256(digest.data(), pre.data(), pre.size());
    return digest;
}

std::optional<double> theta(std::span<const std::uint8_t> seed,
                            std::uint64_t phase,
                            double theta_min,
                            double theta_max) {
    const std::optional<std::array<std::uint8_t, 32>> digest = theta_digest(seed, phase);
    if (!digest) return std::nullopt;

    // Go NewSelector's normalization, in the same order and with the same
    // comparisons. A node configured out of range does not run a different
    // protocol; it runs this one.
    if (theta_min <= 0 || theta_min >= 1) theta_min = kThetaMin;
    if (theta_max <= theta_min || theta_max > 1) theta_max = kThetaMax;

    // Go: float64(hashUint) / float64(^uint64(0)). Both conversions round to
    // nearest, and ^uint64(0) converts to exactly 2⁶⁴, so this reads slightly
    // below 1 and never reaches it.
    const double normalized =
        static_cast<double>(be64(digest->data())) / static_cast<double>(~std::uint64_t{0});
    return theta_min + normalized * (theta_max - theta_min);
}

std::optional<int> alpha(std::span<const std::uint8_t> seed,
                         std::uint64_t phase,
                         std::uint32_t k,
                         double theta_min,
                         double theta_max) {
    const std::optional<double> t = theta(seed, phase, theta_min, theta_max);
    if (!t) return std::nullopt;
    return alpha_threshold(k, *t);
}

}  // namespace lux::consensus::fpc
