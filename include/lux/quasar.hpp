// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness BLS verification — C++ surface.
//
// The Go reference is `protocol/quasar/quasar.go` (signer.VerifyThresholdSignatureBytes
// and AggregateThresholdSignatures). The cryptographic kernel is the
// IRTF BLS12-381 signature primitive with the "BLS_SIG" ciphersuite
// (NUL DST). Pubkeys live on G1 (48-byte Zcash compressed), signatures
// on G2 (96-byte Zcash compressed), hash-to-G2 via SSWU per RFC 9380.
//
// This is the hot path for finalised-round verification — every
// finalised block walks through `WitnessVerifier::verify` exactly once
// (twice if there's a re-verify on cert receipt). The C ABI in
// `quasar.h` is the only external contract; this header is the
// in-process surface for C++ consumers (tests, benchmarks).
//
// Backend selection (`Backend::Cpu` today, `Backend::Gpu` reserved):
//   the verify path stays CPU-only for now — pairings are a tight
//   inner loop where the blst optimised assembly dominates anything
//   we can write in CUDA without batching, and per-round verify is
//   inherently latency-bound. A batched verifier that amortises
//   final_exp across many certs can swap in behind the same enum
//   without changing the call sites.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "quasar.h"

namespace lux::quasar {

constexpr std::size_t kPubKeyLen   = LUX_QUASAR_PK_LEN;   // 48
constexpr std::size_t kSignatureLen = LUX_QUASAR_SIG_LEN; // 96
constexpr std::size_t kShareLen     = 4 + kSignatureLen;  // 100 (u32 index || G2)

enum class Backend : std::uint8_t {
    Cpu = 0,  // blst CPU — the only path today
    Gpu = 1,  // reserved — future batched pairing oracle
};

enum class Status : std::int32_t {
    Ok           = LUX_QUASAR_OK,
    ErrInvalid   = LUX_QUASAR_ERR_INVALID,
    ErrSignature = LUX_QUASAR_ERR_SIG,
    ErrVerify    = LUX_QUASAR_ERR_VERIFY,
};

// WitnessVerifier — one verifier instance per chain / per validator
// set. Holds the bound group public key and pre-parsed affine form to
// keep `verify()` allocation-free on the success path. Mutation of the
// group key is not supported on a live verifier; a validator-set
// rotation constructs a fresh `WitnessVerifier` (mirrors Go's
// `NewVerifier`).
class WitnessVerifier {
public:
    // Construct with the 48-byte compressed group public key. Throws
    // std::invalid_argument if the bytes do not deserialise to a valid
    // G1 point or fail the subgroup check.
    explicit WitnessVerifier(std::span<const std::uint8_t, kPubKeyLen> group_key,
                             Backend backend = Backend::Cpu);

    WitnessVerifier(const WitnessVerifier&) = delete;
    WitnessVerifier& operator=(const WitnessVerifier&) = delete;
    WitnessVerifier(WitnessVerifier&&) noexcept;
    WitnessVerifier& operator=(WitnessVerifier&&) noexcept;
    ~WitnessVerifier();

    // Verify `sig` over `msg`. Returns Status::Ok on a verifying
    // signature, Status::ErrSignature if `sig` is not a valid G2
    // curve point, Status::ErrVerify if the pairing rejects.
    [[nodiscard]] Status verify(std::span<const std::uint8_t> msg,
                                std::span<const std::uint8_t, kSignatureLen> sig) const noexcept;

    // Convenience overload for non-fixed-extent signature spans.
    [[nodiscard]] Status verify(std::span<const std::uint8_t> msg,
                                std::span<const std::uint8_t> sig) const noexcept;

    [[nodiscard]] Backend backend() const noexcept { return backend_; }

private:
    struct Impl;
    Impl* impl_ {nullptr};   // owning, allocated in ctor (pImpl to keep blst out of header)
    Backend backend_ {Backend::Cpu};
};

// WitnessAggregator — combines threshold-signature shares into a
// single aggregated G2 signature. Holds the bound group public key for
// future Lagrange-weighted aggregation; today the aggregation is the
// n-of-n branch the Go aggregator takes when every Lagrange
// coefficient reduces to 1 (i.e. the caller has pre-applied weights).
class WitnessAggregator {
public:
    explicit WitnessAggregator(std::span<const std::uint8_t, kPubKeyLen> group_key,
                               Backend backend = Backend::Cpu);

    WitnessAggregator(const WitnessAggregator&) = delete;
    WitnessAggregator& operator=(const WitnessAggregator&) = delete;
    WitnessAggregator(WitnessAggregator&&) noexcept;
    WitnessAggregator& operator=(WitnessAggregator&&) noexcept;
    ~WitnessAggregator();

    // Aggregate `n` shares laid out as (u32 index || 96-byte sig) records.
    // Writes the 96-byte aggregated G2 signature to `out_sig`. Returns
    // Status::Ok on success; Status::ErrSignature if any share fails
    // subgroup check.
    [[nodiscard]] Status aggregate(std::span<const std::uint8_t> shares_packed,
                                   std::size_t n,
                                   std::span<std::uint8_t, kSignatureLen> out_sig) const noexcept;

    [[nodiscard]] Backend backend() const noexcept { return backend_; }

private:
    struct Impl;
    Impl* impl_ {nullptr};
    Backend backend_ {Backend::Cpu};
};

// Free-function fast path — for one-shot verifies that don't want to
// build a WitnessVerifier. Construct + verify + destruct. Same
// semantics as the C entry point `lux_quasar_witness_verify`.
[[nodiscard]] Status
verify_once(std::span<const std::uint8_t, kPubKeyLen>    group_key,
            std::span<const std::uint8_t>                 msg,
            std::span<const std::uint8_t, kSignatureLen>  sig) noexcept;

// DST string — exposed so test code can confirm parity with the Go
// side without re-encoding the string literal in every test.
constexpr const char* kDstSignature =
    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
constexpr std::size_t kDstSignatureLen = 43;  // strlen, must match Go's len()

}  // namespace lux::quasar
