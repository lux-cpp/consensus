// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// bls.cpp — the Lux consensus vote domain over blst. See bls.hpp for why the
// domain, and only the domain, differs from the reused eth2 precompile surface.

#include "lux/consensus/bls.hpp"

#include "bls_signature.hpp"  // cevm::crypto::bls — reused, domain-free bodies

#include <blst.h>
#include <cstring>

#include <cstddef>
#include <optional>
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

namespace lux::consensus::bls {

namespace {

// The key leg, DECODED: the point, or nothing. One definition, and it hands back
// what it decoded so the caller that needs the point does not decode it twice.
//
// Canonical compressed G1, in the prime-order subgroup, not the identity. blst's
// uncompress refuses a non-canonical (x >= p) spelling; in_g1 refuses an
// off-subgroup point; is_inf refuses the identity that the Go/Rust oracles also
// reject at this leg.
std::optional<blst_p1_affine> decode_key(const std::uint8_t pk[48]) noexcept {
    if (pk == nullptr) return std::nullopt;
    blst_p1_affine aff;
    if (blst_p1_uncompress(&aff, pk) != BLST_SUCCESS) return std::nullopt;
    if (!blst_p1_affine_in_g1(&aff)) return std::nullopt;
    if (blst_p1_affine_is_inf(&aff)) return std::nullopt;
    // One point, one encoding. A decoder that accepted a second spelling of the
    // same key would let a registrant choose which 48 bytes the message carries,
    // and the proof is over the caller's bytes. Go checks this at the same leg,
    // between decoding the key and decoding the proof, so a key that decodes but
    // does not round-trip is Key on both sides and not Proof on one of them.
    // blst refuses a non-canonical x on the way in, so this is a wall behind a
    // wall — which is where it belongs, and not at one caller's discretion.
    std::uint8_t round_trip[48];
    blst_p1_affine_compress(round_trip, &aff);
    if (std::memcmp(round_trip, pk, sizeof(round_trip)) != 0) return std::nullopt;
    return aff;
}

}  // namespace

bool key_validate(const std::uint8_t pk[48]) noexcept { return decode_key(pk).has_value(); }

Pop pop_verify(const std::uint8_t node[20], const std::uint8_t pk[48],
               const std::uint8_t proof[96]) noexcept {
    if (node == nullptr || proof == nullptr) return Pop::Key;

    // ENCODING of the key — the whole of it, in one place, shared with the gate's
    // constructor so the two cannot come to disagree about what a key is.
    const std::optional<blst_p1_affine> decoded = decode_key(pk);
    if (!decoded) return Pop::Key;
    const blst_p1_affine pk_aff = *decoded;

    // ENCODING of the proof: canonical compressed G2, in-subgroup, non-identity.
    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, proof) != BLST_SUCCESS) return Pop::Proof;
    if (!blst_p2_affine_in_g2(&sig_aff)) return Pop::Proof;
    if (blst_p2_affine_is_inf(&sig_aff)) return Pop::Proof;

    // POSSESSION: the proof signs node ‖ key, 68 bytes, under the POP domain.
    std::uint8_t msg[kNodeLen + 48];
    std::memcpy(msg, node, kNodeLen);
    std::memcpy(msg + kNodeLen, pk, 48);
    const BLST_ERROR rc = blst_core_verify_pk_in_g1(
        &pk_aff, &sig_aff, /*hash_or_encode=*/true, msg, sizeof(msg),
        reinterpret_cast<const std::uint8_t*>(kPopDST), kPopDSTLen,
        /*aug=*/nullptr, /*aug_len=*/0);
    return rc == BLST_SUCCESS ? Pop::Ok : Pop::Possession;
}

}  // namespace lux::consensus::bls
