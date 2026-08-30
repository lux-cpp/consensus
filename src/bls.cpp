// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// bls.cpp — the Lux consensus vote domain over blst. See bls.hpp for why the
// domain, and only the domain, differs from the reused eth2 precompile surface.

#include "lux/consensus/bls.hpp"

#include "bls_signature.hpp"  // cevm::crypto::bls — reused, domain-free bodies

#include <blst.h>

#include <cstddef>
#include <vector>

namespace lux::consensus::bls {

namespace {

const std::uint8_t* dst() noexcept {
    return reinterpret_cast<const std::uint8_t*>(kVoteDST);
}

bool is_zero(const std::uint8_t* b, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i)
        if (b[i] != 0) return false;
    return true;
}

// Decode a 32-byte big-endian secret key with the IRTF range check.
bool load_sk(blst_scalar& out, const std::uint8_t sk[32]) noexcept {
    if (is_zero(sk, 32)) return false;
    blst_scalar_from_bendian(&out, sk);
    return blst_sk_check(&out);
}

}  // namespace

int keygen(const std::uint8_t seed[32], std::uint8_t sk[32]) noexcept {
    return cevm::crypto::bls::keygen(seed, sk);
}

int sk_to_pk(const std::uint8_t sk[32], std::uint8_t pk[48]) noexcept {
    return cevm::crypto::bls::sk_to_pk(sk, pk);
}

int aggregate_sigs(const std::uint8_t* sigs, std::size_t n, std::uint8_t agg_sig[96]) noexcept {
    return cevm::crypto::bls::aggregate_sigs(sigs, n, agg_sig);
}

int sign(const std::uint8_t sk[32], const std::uint8_t* msg, std::size_t msg_len,
         std::uint8_t sig[96]) noexcept {
    if (sk == nullptr || sig == nullptr) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    blst_scalar s;
    if (!load_sk(s, sk)) return -1;
    blst_p2 hash_jac;
    blst_hash_to_g2(&hash_jac, msg, msg_len, dst(), kVoteDSTLen, /*aug=*/nullptr, /*aug_len=*/0);
    blst_p2 sig_jac;
    blst_sign_pk_in_g1(&sig_jac, &hash_jac, &s);
    blst_p2_compress(sig, &sig_jac);
    return 0;
}

bool pair(const blst_p1_affine& pk, const blst_p2_affine& sig,
          const std::uint8_t* msg, std::size_t msg_len) noexcept {
    // blst_pairing is opaque, alignment-sensitive, and sized at RUNTIME — 3192
    // bytes in this build. A fixed buffer would be a number that can go stale,
    // and the first draft of this function guessed 1024 and silently refused
    // every valid signature until the corpus said so. So the arena is sized by
    // asking, once per thread, and its element type carries the alignment.
    static thread_local std::vector<std::max_align_t> arena(
        (blst_pairing_sizeof() + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    auto* ctx = reinterpret_cast<blst_pairing*>(arena.data());

    blst_pairing_init(ctx, /*hash_or_encode=*/true, dst(), kVoteDSTLen);
    // The public key side only: e(pk, H(msg)) into the Miller accumulator.
    if (blst_pairing_aggregate_pk_in_g1(ctx, &pk, /*signature=*/nullptr,
                                        msg, msg_len, /*aug=*/nullptr, 0) != BLST_SUCCESS)
        return false;
    blst_pairing_commit(ctx);

    // The signature side against the fixed generator, which blst pairs faster
    // than a generic point.
    blst_fp12 gt;
    blst_aggregated_in_g2(&gt, &sig);
    return blst_pairing_finalverify(ctx, &gt);
}

int verify(const std::uint8_t pk[48], const std::uint8_t* msg, std::size_t msg_len,
           const std::uint8_t sig[96]) noexcept {
    if (pk == nullptr || sig == nullptr) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    blst_p1_affine pk_aff;
    if (blst_p1_uncompress(&pk_aff, pk) != BLST_SUCCESS) return -1;
    if (!blst_p1_affine_in_g1(&pk_aff)) return 1;
    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, sig) != BLST_SUCCESS) return -1;
    if (!blst_p2_affine_in_g2(&sig_aff)) return 1;
    return pair(pk_aff, sig_aff, msg, msg_len) ? 0 : 1;
}

int fast_aggregate_verify(const std::uint8_t* pks, std::size_t n,
                          const std::uint8_t* msg, std::size_t msg_len,
                          const std::uint8_t agg_sig[96]) noexcept {
    if (pks == nullptr || agg_sig == nullptr || n == 0) return -1;
    if (msg == nullptr && msg_len != 0) return -1;
    std::uint8_t agg_pk[48];
    // Pubkey aggregation is point addition — no hash-to-curve, no domain. Reused.
    const int rc = cevm::crypto::bls::aggregate_pubkeys(pks, n, agg_pk);
    if (rc != 0) return rc;
    return verify(agg_pk, msg, msg_len, agg_sig);
}

}  // namespace lux::consensus::bls
