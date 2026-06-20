// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness BLS verification — extern "C" shim. One file, one
// translation unit. Wraps the C++ surface in `quasar.hpp` for the cgo
// bridge. No state, no allocation; pure forwarders.

#include "lux/quasar.h"
#include "lux/quasar.hpp"

#include <span>
#include <stdexcept>

extern "C" {

lux_quasar_status
lux_quasar_witness_verify(const uint8_t* group_key, size_t group_key_len,
                          const uint8_t* msg,       size_t msg_len,
                          const uint8_t* sig,       size_t sig_len) {
    if (group_key == nullptr || sig == nullptr) {
        return LUX_QUASAR_ERR_INVALID;
    }
    if (group_key_len != LUX_QUASAR_PK_LEN || sig_len != LUX_QUASAR_SIG_LEN) {
        return LUX_QUASAR_ERR_INVALID;
    }
    if (msg == nullptr && msg_len != 0) {
        return LUX_QUASAR_ERR_INVALID;
    }
    const auto st = lux::quasar::verify_once(
        std::span<const uint8_t, lux::quasar::kPubKeyLen>(group_key, lux::quasar::kPubKeyLen),
        std::span<const uint8_t>(msg, msg_len),
        std::span<const uint8_t, lux::quasar::kSignatureLen>(sig, lux::quasar::kSignatureLen));
    return static_cast<lux_quasar_status>(st);
}

lux_quasar_status
lux_quasar_witness_aggregate(const uint8_t* group_key, size_t group_key_len,
                             const uint8_t* shares,    size_t shares_n,
                             uint8_t out_sig[96]) {
    if (group_key == nullptr || shares == nullptr || out_sig == nullptr) {
        return LUX_QUASAR_ERR_INVALID;
    }
    if (group_key_len != LUX_QUASAR_PK_LEN) {
        return LUX_QUASAR_ERR_INVALID;
    }
    if (shares_n == 0) {
        return LUX_QUASAR_ERR_INVALID;
    }
    try {
        const lux::quasar::WitnessAggregator agg(
            std::span<const uint8_t, lux::quasar::kPubKeyLen>(group_key, lux::quasar::kPubKeyLen));
        const auto st = agg.aggregate(
            std::span<const uint8_t>(shares, shares_n * lux::quasar::kShareLen),
            shares_n,
            std::span<uint8_t, lux::quasar::kSignatureLen>(out_sig, lux::quasar::kSignatureLen));
        return static_cast<lux_quasar_status>(st);
    } catch (const std::invalid_argument&) {
        return LUX_QUASAR_ERR_SIG;
    }
}

const char* lux_quasar_status_str(lux_quasar_status s) {
    switch (s) {
        case LUX_QUASAR_OK:          return "ok";
        case LUX_QUASAR_ERR_INVALID: return "invalid argument";
        case LUX_QUASAR_ERR_SIG:     return "signature or pubkey decode failed";
        case LUX_QUASAR_ERR_VERIFY:  return "signature did not verify";
        default:                     return "unknown";
    }
}

uint32_t lux_quasar_abi_version(void) {
    return LUX_QUASAR_ABI_VERSION;
}

}  // extern "C"
