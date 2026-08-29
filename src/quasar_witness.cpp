// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness threshold-share aggregator — CPU implementation.
//
// Reference (Go): `luxfi/crypto/bls/bls_c.go::AggregateSignatures`
//   for _, sig := range sigs {
//       if !agg.Add(sig.sig, /*subgroup_check=*/true) { ... error ... }
//   }
//   return agg.ToAffine().Compress()
//
// Wire layout for the C ABI:
//   N records of (u32 big-endian index || 96-byte compressed G2 sig).
//   The 4-byte index is consumed and discarded here — Lagrange
//   weighting is applied on the Go side by `aggregateWithLagrange`
//   (luxfi/crypto/threshold/bls/scheme.go) when t < n, so by the time
//   shares reach this aggregator each share is already scaled. The
//   sum-of-shares branch this implements matches the n-of-n
//   `allOnes` case of the Go aggregator (scheme.go:790-805).

#include "lux/quasar.hpp"

#include <blst.h>

#include <cstring>
#include <stdexcept>
#include <utility>

namespace lux::quasar {

namespace {

bool is_compressed_identity_g1_for_aggregator(const std::uint8_t pk[48]) noexcept {
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

struct WitnessAggregator::Impl {
    // Group key parsed once at construction. Currently unused at
    // aggregate-time (we mirror Go's plain Σσ_i path) but kept so the
    // aggregator owns the group binding — future Lagrange-on-our-side
    // implementations will multiply by group-key coefficients in-place
    // without changing the call sites.
    blst_p1_affine group_pk_aff{};
};

WitnessAggregator::WitnessAggregator(std::span<const std::uint8_t, kPubKeyLen> group_key,
                                     Backend backend)
    : impl_(new Impl{}), backend_(backend) {
    if (is_compressed_identity_g1_for_aggregator(group_key.data())) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessAggregator: group key is identity (zero key)");
    }
    if (blst_p1_uncompress(&impl_->group_pk_aff, group_key.data()) != BLST_SUCCESS) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessAggregator: group key not a valid G1 point");
    }
    if (!blst_p1_affine_in_g1(&impl_->group_pk_aff)) {
        delete impl_;
        impl_ = nullptr;
        throw std::invalid_argument("WitnessAggregator: group key fails G1 subgroup check");
    }
}

WitnessAggregator::WitnessAggregator(WitnessAggregator&& other) noexcept
    : impl_(other.impl_), backend_(other.backend_) {
    other.impl_ = nullptr;
}

WitnessAggregator& WitnessAggregator::operator=(WitnessAggregator&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        backend_ = other.backend_;
        other.impl_ = nullptr;
    }
    return *this;
}

WitnessAggregator::~WitnessAggregator() {
    delete impl_;
}

Status WitnessAggregator::aggregate(std::span<const std::uint8_t> shares_packed,
                                    std::size_t n,
                                    std::span<std::uint8_t, kSignatureLen> out_sig) const noexcept {
    if (impl_ == nullptr) return Status::ErrInvalid;
    if (n == 0) return Status::ErrInvalid;
    if (shares_packed.size() != n * kShareLen) return Status::ErrInvalid;

    blst_p2 acc;
    bool acc_init = false;

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t* rec = shares_packed.data() + i * kShareLen;
        // Skip the 4-byte big-endian index; aggregation is sum.
        const std::uint8_t* sig_bytes = rec + 4;

        blst_p2_affine sig_aff;
        if (blst_p2_uncompress(&sig_aff, sig_bytes) != BLST_SUCCESS) {
            return Status::ErrSignature;
        }
        if (!blst_p2_affine_in_g2(&sig_aff)) {
            return Status::ErrSignature;
        }

        if (!acc_init) {
            blst_p2_from_affine(&acc, &sig_aff);
            acc_init = true;
        } else {
            blst_p2_add_or_double_affine(&acc, &acc, &sig_aff);
        }
    }

    blst_p2_compress(out_sig.data(), &acc);
    return Status::Ok;
}

}  // namespace lux::quasar
