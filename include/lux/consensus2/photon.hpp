// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// photon.hpp — committee sampling: draw K distinct validators from a set of N.
// The Lux consensus family's sampling stage. Deterministic given a seed so a
// round is reproducible (in production the seed is round/VRF entropy supplied by
// the caller); there is no global RNG and no wall-clock dependence.
//
// Ported from luxfi/consensus protocol/photon. Header-only — pure index logic,
// no crypto, no allocation beyond the result.

#pragma once

#include <cstdint>
#include <utility>
#include <vector>

namespace lux::consensus2::photon {

// splitmix64 — a tiny, deterministic, well-distributed generator. The seed is
// supplied by the caller (upstream round/VRF entropy); this never reads a global
// or the clock, so sampling is reproducible and testable.
class Rng {
public:
    explicit Rng(std::uint64_t seed) noexcept : s_(seed) {}

    std::uint64_t next() noexcept {
        std::uint64_t z = (s_ += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    // Unbiased index in [0, n) via rejection sampling (no modulo bias).
    std::uint64_t below(std::uint64_t n) noexcept {
        if (n == 0) return 0;
        const std::uint64_t limit = UINT64_MAX - (UINT64_MAX % n);
        std::uint64_t x;
        do { x = next(); } while (x >= limit);
        return x % n;
    }

private:
    std::uint64_t s_;
};

// Sample k DISTINCT indices in [0, n) by partial Fisher–Yates. k is clamped to n
// (you cannot draw more distinct members than exist). Result order is the draw
// order; callers that need a set should treat it as one.
inline std::vector<std::uint32_t> sample(std::uint32_t n, std::uint32_t k, std::uint64_t seed) {
    if (n == 0) return {};
    if (k > n) k = n;
    std::vector<std::uint32_t> pool(n);
    for (std::uint32_t i = 0; i < n; ++i) pool[i] = i;
    Rng rng(seed);
    for (std::uint32_t i = 0; i < k; ++i) {
        const std::uint32_t j = i + static_cast<std::uint32_t>(rng.below(n - i));
        std::swap(pool[i], pool[j]);
    }
    pool.resize(k);
    return pool;
}

}  // namespace lux::consensus2::photon
