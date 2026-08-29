// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// threshold.hpp — the quorum thresholds, in one place, as pure functions.
//
// Two consumers read these and neither owns them: the GATE (quorum_cert_engine)
// enforces the stake floors, the WAVE (wave) sizes its per-round vote threshold
// from the same ⅔ rule. Go keeps them in package config for exactly that reason
// (config/quorum_threshold.go, config/constants.go); a second definition on
// either side is how a count gate drifts from the stake predicate it is meant to
// track. There is one definition, here, and both sides call it.
//
// Every function is total, overflow-free and side-effect free.

#pragma once

#include <cstdint>

namespace lux::consensus2 {

// The 69% per-round agreement threshold (LP-CONSENSUS-69) — Go
// config.ConsensusSuperMajority. This is the SAMPLING threshold, not the stake
// supermajority: it sizes how many of K sampled peers must agree in one round.
inline constexpr double kConsensusSuperMajority = 0.69;

// The smallest Byzantine-fault-tolerant committee: K=4, f=1. Go
// engine/chain.minBFTCommittee. A committee floors here rather than shrinking
// into a set that cannot tolerate a single fault.
inline constexpr std::uint32_t kMinBFTCommittee = 4;

// floor(2·total/3) — Go config.TwoThirdsStakeFloor. The QUASAR (export) stake
// floor; the predicate is voted > two_thirds_stake_floor(total). Computed as
// total = 3q+r ⇒ 2q + (r==2 ? 1 : 0), so it never overflows on a large total.
[[nodiscard]] std::uint64_t two_thirds_stake_floor(std::uint64_t total) noexcept;

// floor(total/2) — Go config.HalfStakeFloor. The NOVA (local execution) stake
// floor; the predicate is voted > half_stake_floor(total). One rung lower: two
// majorities of one set always intersect, which is the crash-fault safety Nova
// rests on, while only Quasar's ⅔ is Byzantine-safe.
[[nodiscard]] std::uint64_t half_stake_floor(std::uint64_t total) noexcept;

// The smallest vote count that can strictly exceed ⅔ of n equal weights —
// floor(2n/3)+1. Go config.EqualStakeSupermajorityThreshold. n=5→4, n=11→8,
// n=21→15 (15, not 14: 14/21 does NOT strictly exceed ⅔).
[[nodiscard]] std::uint32_t equal_stake_supermajority(std::uint32_t n) noexcept;

// ⌊n/2⌋+1 — Go engine/chain.NovaQuorum. n<1 → 1 (never 0, which would let a
// transiently-empty validator view self-accept).
[[nodiscard]] std::uint32_t nova_quorum(std::uint32_t n) noexcept;

// The minimum DISTINCT signers a Nova cert needs regardless of how stake is
// distributed — Go engine/chain.NovaSignerFloor. nova_quorum of the minimal BFT
// committee (3), capped by the majority of the live set so a genuinely small
// chain stays satisfiable. The guard the stake predicate cannot give: a single
// validator holding a stake majority must not self-ignite.
[[nodiscard]] std::uint32_t nova_signer_floor(std::uint32_t n) noexcept;

// The per-round vote threshold for a committee of k at ratio alpha —
// ceil(k·alpha), Go config.AlphaForK and the fixed-threshold branch of
// wave.Tick. CEIL, never truncation: truncating puts every profile one vote
// under its declared threshold.
[[nodiscard]] int alpha_threshold(std::uint32_t k, double alpha) noexcept;

}  // namespace lux::consensus2
