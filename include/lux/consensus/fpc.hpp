// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// fpc.hpp — where the per-round vote threshold comes from.
//
// threshold.hpp holds the FIXED thresholds: given a ratio, how many votes. This
// holds the ADAPTIVE one — where the ratio itself comes from. Go's
// protocol/wave/fpc derives θ per phase from a per-epoch seed, and α = ⌈θ·k⌉ is
// the count a round accepts on. Two nodes that derive different seeds demand
// different majorities of the same committee, so this is not a tuning knob; it
// is the number agreement is defined in terms of.
//
// The seed is derived, never drawn. It binds the epoch, the chain and the hash
// of the last block the previous epoch finalized — a value nobody holds while
// the current epoch is still open, so no party reads next epoch's thresholds
// early. (luxfi/conformance RULINGS.md §1.)
//
// Everything here is a pure function of its arguments. Refusal is expressible:
// Go's NewSelector rejects an empty seed, so these return nullopt rather than
// hashing nothing and returning a number that looks like an answer.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace lux::consensus::fpc {

// The label the epoch seed is taken under, so this digest cannot collide with
// any other the protocol takes over similar bytes. Go fpc.seedDomain.
inline constexpr std::string_view kSeedDomain = "lux.consensus.fpc.seed";

// Go fpc.NewSelector's defaults, and what it substitutes for a θ interval it
// refuses. θ never leaves [0.5, 0.8] on a default-configured node.
inline constexpr double kThetaMin = 0.5;
inline constexpr double kThetaMax = 0.8;

// The exact bytes epoch_seed hashes — Go fpc.EpochSeedPreimage.
//
//     domain ‖ be64(epoch) ‖ be64(len(chain)) ‖ chain
//                          ‖ be64(len(parent)) ‖ parent
//
// Every variable-length field is written at its length, so the preimage reads
// back apart into exactly the triple that produced it. Written end to end it
// would not: a chain naming itself `chain‖H` binds no parent and still derives
// what `chain` derives at parent `H` — trading away the one input nobody can
// know in advance for a name the chain picks for itself.
//
// It is exported because the corpus records these bytes and not only the
// digest. Two implementations can agree on every digest in a corpus and still
// disagree on the first input that is not in it; they cannot, if they agree on
// what they hashed.
[[nodiscard]] std::vector<std::uint8_t> seed_preimage(std::uint64_t epoch,
                                                      std::span<const std::uint8_t> chain,
                                                      std::span<const std::uint8_t> parent);

// sha256(seed_preimage(...)) — Go fpc.DeriveEpochSeed.
[[nodiscard]] std::array<std::uint8_t, 32> epoch_seed(std::uint64_t epoch,
                                                      std::span<const std::uint8_t> chain,
                                                      std::span<const std::uint8_t> parent);

// The digest θ is read out of — sha256(seed ‖ be64(phase)). Go computes it
// inline in Selector.computeTheta; it is named here for the same reason
// seed_preimage is: the corpus records it, so a port that hashes the wrong
// bytes fails on the bytes rather than on the last bit of a float.
//
// nullopt when the seed is empty — see theta().
[[nodiscard]] std::optional<std::array<std::uint8_t, 32>> theta_digest(
    std::span<const std::uint8_t> seed, std::uint64_t phase);

// θ(phase) — Go fpc.Selector.Theta.
//
//     θ = min + be64(sha256(seed ‖ be64(phase))[:8]) / 2⁶⁴ · (max − min)
//
// theta_min and theta_max are normalized exactly as Go's NewSelector does: a
// min outside (0,1) becomes 0.5, a max not above min or above 1 becomes 0.8.
// The normalization lives here and not at the call sites, because a second copy
// of it is a second protocol.
//
// nullopt when the seed is empty. Go returns ErrEmptySeed there; hashing
// nothing would return a number that looks like a threshold and is not one.
[[nodiscard]] std::optional<double> theta(std::span<const std::uint8_t> seed,
                                          std::uint64_t phase,
                                          double theta_min = kThetaMin,
                                          double theta_max = kThetaMax);

// α = ⌈θ(phase)·k⌉ — Go fpc.Selector.SelectThreshold. The count of votes a
// round at this phase accepts on. Composed of theta() and threshold.hpp's
// alpha_threshold, so the adaptive and fixed paths round the same way.
[[nodiscard]] std::optional<int> alpha(std::span<const std::uint8_t> seed,
                                       std::uint64_t phase,
                                       std::uint32_t k,
                                       double theta_min = kThetaMin,
                                       double theta_max = kThetaMax);

}  // namespace lux::consensus::fpc
