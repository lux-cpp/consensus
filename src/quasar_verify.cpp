// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness BLS verification — CPU implementation.
//
// Hot path: `WitnessVerifier::verify` runs once per finalised round.
// Optimisation discipline:
//   - The compressed group public key is parsed and subgroup-checked
//     once at construction; affine form is cached.
//   - `verify()` is allocation-free: blst's `blst_core_verify_pk_in_g1`
//     takes the affine pk/sig directly and accepts the raw msg+DST
//     bytes, so we hand it stack data and the cached pk.
//   - Subgroup checks on sig are forced on (RFC 9380 §4.1 — without
//     them an attacker can present a non-subgroup point that pairs to
//     the identity).
//
// Reference (Go): `luxfi/crypto/bls/bls_c.go::Verify`
//   sig.sig.Verify(true /*hash_or_encode*/, pk.pk, false /*pk_validate*/,
//                  msg, dstSignature)
// where `dstSignature = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"`.
//
// We use `blst_p1_affine_in_g1` for the pk subgroup check (matches
// blst-go's `pk.Validate()`) and `blst_p2_affine_in_g2` for the sig
// check (matches blst-go's `sig.SigValidate(false)`).

#include "lux/quasar.hpp"

#include <blst.h>

#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>

namespace lux::quasar {

namespace {

// IRTF BLS_SIG ciphersuite with NUL augmentation (signature variant,
// not POP). Must match Go's `dstSignature` byte-for-byte. The length
// constant is checked against strlen at compile time to catch typos.
//
// reinterpret_cast on a string literal is not allowed in a constant
// expression, so `kDST` is a regular `const` (linkage-internal). The
// length stays constexpr for static_assert.
const std::uint8_t* const kDST =
    reinterpret_cast<const std::uint8_t*>(kDstSignature);
constexpr std::size_t kDSTLen = kDstSignatureLen;

static_assert(kDSTLen == 43, "BLS_SIG NUL DST length must be 43 bytes");

// Identity-point rejection — Go's `isIdentityG1` checks for all-zero
// compressed bytes. blst's `blst_p1_uncompress` accepts the identity
// (Zcash compressed identity is the high bit set + all zeros), so we
// reject explicitly to match Go semantics.
bool is_compressed_identity_g1(const std::uint8_t pk[48]) noexcept {
    // Zcash compressed identity: 0xC0 | <47 zero bytes>.
    // Also reject the all-zero encoding to be safe.
    if (pk[0] == 0xC0) {
        for (std::size_t i = 1; i < 48; ++i) {
            if (pk[i] != 0) return false;
        }
        return true;
    }
    for (std::size_t i = 0; i < 48; ++i) {
        if (pk[i] != 0) return false;
    }
    return true;
}

}  // namespace

// pImpl keeps blst types out of the header. The verifier owns one
// affine pk and the backend tag. Trivially relocatable — move
// constructor just swaps the pointer.
struct WitnessVerifier::Impl {
    blst_p1_affine pk_aff{};
};

WitnessVerifier::WitnessVerifier(std::span<const std::uint8_t, kPubKeyLen> group_key,
                                 Backend backend)
    : impl_(new Impl{}), backend_(backend) {
    if (is_compressed_identity_g1(group_key.data())) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessVerifier: group key is identity (zero key)");
    }
    if (blst_p1_uncompress(&impl_->pk_aff, group_key.data()) != BLST_SUCCESS) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessVerifier: group key not a valid G1 point");
    }
    if (!blst_p1_affine_in_g1(&impl_->pk_aff)) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessVerifier: group key fails G1 subgroup check");
    }
}

WitnessVerifier::WitnessVerifier(WitnessVerifier&& other) noexcept
    : impl_(other.impl_), backend_(other.backend_) {
    other.impl_ = nullptr;
}

WitnessVerifier& WitnessVerifier::operator=(WitnessVerifier&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        backend_ = other.backend_;
        other.impl_ = nullptr;
    }
    return *this;
}

WitnessVerifier::~WitnessVerifier() {
    delete impl_;
}

Status WitnessVerifier::verify(std::span<const std::uint8_t> msg,
                               std::span<const std::uint8_t, kSignatureLen> sig) const noexcept {
    if (impl_ == nullptr) return Status::ErrInvalid;

    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, sig.data()) != BLST_SUCCESS) {
        return Status::ErrSignature;
    }
    if (!blst_p2_affine_in_g2(&sig_aff)) {
        return Status::ErrSignature;
    }

    const BLST_ERROR rc = blst_core_verify_pk_in_g1(
        &impl_->pk_aff, &sig_aff,
        /*hash_or_encode=*/true,
        msg.data(), msg.size(),
        kDST, kDSTLen,
        /*aug=*/nullptr, /*aug_len=*/0);

    return (rc == BLST_SUCCESS) ? Status::Ok : Status::ErrVerify;
}

Status WitnessVerifier::verify(std::span<const std::uint8_t> msg,
                               std::span<const std::uint8_t> sig) const noexcept {
    if (sig.size() != kSignatureLen) return Status::ErrInvalid;
    return verify(msg, std::span<const std::uint8_t, kSignatureLen>(sig.data(), kSignatureLen));
}

Status verify_once(std::span<const std::uint8_t, kPubKeyLen>    group_key,
                   std::span<const std::uint8_t>                 msg,
                   std::span<const std::uint8_t, kSignatureLen>  sig) noexcept {
    // Inline the parse + verify so the one-shot path doesn't pay for
    // an Impl heap allocation. Mirrors the per-call body of the
    // existing `cevm::crypto::bls::verify` (POP-DST variant) but with
    // the NUL DST + Quasar-status return.
    if (is_compressed_identity_g1(group_key.data())) {
        return Status::ErrSignature;
    }
    blst_p1_affine pk_aff;
    if (blst_p1_uncompress(&pk_aff, group_key.data()) != BLST_SUCCESS) {
        return Status::ErrSignature;
    }
    if (!blst_p1_affine_in_g1(&pk_aff)) {
        return Status::ErrSignature;
    }
    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, sig.data()) != BLST_SUCCESS) {
        return Status::ErrSignature;
    }
    if (!blst_p2_affine_in_g2(&sig_aff)) {
        return Status::ErrSignature;
    }
    const BLST_ERROR rc = blst_core_verify_pk_in_g1(
        &pk_aff, &sig_aff,
        /*hash_or_encode=*/true,
        msg.data(), msg.size(),
        kDST, kDSTLen,
        /*aug=*/nullptr, /*aug_len=*/0);
    return (rc == BLST_SUCCESS) ? Status::Ok : Status::ErrVerify;
}

}  // namespace lux::quasar
