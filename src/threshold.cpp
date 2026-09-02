// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// threshold.cpp — the quorum thresholds. Pure arithmetic; see threshold.hpp for
// which Go definition each one mirrors.

#include "lux/consensus/threshold.hpp"

#include <cmath>

namespace lux::consensus {

std::uint64_t two_thirds_stake_floor(std::uint64_t total) noexcept {
    const std::uint64_t q = total / 3;
    const std::uint64_t r = total % 3;
    std::uint64_t floor = 2 * q;
    if (r == 2) ++floor;  // floor(2r/3): r∈{0,1}→0, r==2→1
    return floor;
}

std::uint64_t half_stake_floor(std::uint64_t total) noexcept { return total / 2; }

std::uint32_t two_thirds_count(std::uint32_t n) noexcept {
    if (n == 0) return 1;
    return static_cast<std::uint32_t>(two_thirds_stake_floor(n)) + 1;
}

std::uint32_t nova_quorum(std::uint32_t n) noexcept { return n < 1 ? 1 : n / 2 + 1; }

std::uint32_t nova_signer_floor(std::uint32_t n) noexcept {
    const std::uint32_t q = nova_quorum(n);
    const std::uint32_t cap = nova_quorum(kMinBFTCommittee);  // 3
    return q < cap ? q : cap;
}

int alpha_threshold(std::uint32_t k, double alpha) noexcept {
    return static_cast<int>(std::ceil(static_cast<double>(k) * alpha));
}

}  // namespace lux::consensus
