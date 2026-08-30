// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// bls.hpp — the ONE BLS surface consensus signs and verifies through.
//
// THE DOMAIN IS THE WHOLE POINT. A BLS signature is a hash-to-curve under a
// domain separation tag; two implementations that agree on every byte of the
// message and disagree on the tag produce different signatures and reject each
// other. The Go node signs consensus votes under the BASIC ciphersuite tag
//
//     BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
//
// (luxfi/crypto bls.dstSignature, used by bls.Sign/bls.Verify). The reused
// cevm::crypto::bls surface is the ETH2 PRECOMPILE ciphersuite and is hard-wired
// to ..._RO_POP_ — correct for its own domain, wrong for a consensus vote. Same
// key, same message, different signature; proven to reject bidirectionally.
//
// So consensus has exactly one BLS surface and it knows exactly one domain:
// the Lux consensus vote domain. Behind it:
//
//   - the DOMAIN-BOUND operations (sign, verify, fast_aggregate_verify) hash to
//     the curve under kVoteDST and are implemented here against blst — the same
//     proven library the Go node reaches through supranational/blst. No scheme
//     is invented; only the tag differs from the reused surface.
//   - the DOMAIN-FREE operations (keygen, sk_to_pk, aggregate_sigs) are pure
//     point arithmetic with no hash-to-curve, so they are the reused
//     cevm::crypto::bls bodies unchanged, forwarded.
//
// Aggregation is sound over a common message under the basic ciphersuite ONLY
// when every public key admitted to the set has had a proof-of-possession
// verified upstream (P-chain admission, luxfi/crypto VerifyProofOfPossession).
// The gate trusts the admitted set, exactly as the Go engine does.
//
// Convention, inherited unchanged: 0 on success, 1 on verification mismatch,
// <0 on decode/length/null error.

#pragma once

#include <blst.h>

#include <cstddef>
#include <cstdint>

namespace lux::consensus::bls {

// The Lux consensus vote ciphersuite — byte-identical to Go luxfi/crypto
// bls.dstSignature. Exposed so a conformance test can assert the tag itself.
inline constexpr char        kVoteDST[]  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
inline constexpr std::size_t kVoteDSTLen = sizeof(kVoteDST) - 1;  // 43, drops the C terminator

// Domain-free (no hash-to-curve): reused bodies, forwarded.
int keygen(const std::uint8_t seed[32], std::uint8_t sk[32]) noexcept;
int sk_to_pk(const std::uint8_t sk[32], std::uint8_t pk[48]) noexcept;
int aggregate_sigs(const std::uint8_t* sigs, std::size_t n, std::uint8_t agg_sig[96]) noexcept;

// Domain-bound (hash-to-curve under kVoteDST): the Lux consensus vote domain.
int sign(const std::uint8_t sk[32], const std::uint8_t* msg, std::size_t msg_len,
         std::uint8_t sig[96]) noexcept;
// The pairing itself, over points already decompressed and already group-checked.
// ONE definition: the byte-oriented verify below and every caller that already
// holds decompressed points (a validator set, an aggregate) go through here, so
// there is exactly one place that decides how a signature is checked.
//
// It is deliberately NOT blst_core_verify_pk_in_g1. That entry point pairs both
// points in one generic multi-Miller loop; this accumulates only e(pk, H(m))
// and pairs the signature against the FIXED generator, which blst does faster.
// Measured against the identical libblst.a on this host: 731.3 us the direct
// way, 671.3 us this way, per signature. It is also the path the Go and Rust
// blst bindings take, so a verification here is the same work as a verification
// there — the earlier gap between the legs was this choice, not the language.
[[nodiscard]] bool pair(const blst_p1_affine& pk, const blst_p2_affine& sig,
                        const std::uint8_t* msg, std::size_t msg_len) noexcept;

int verify(const std::uint8_t pk[48], const std::uint8_t* msg, std::size_t msg_len,
           const std::uint8_t sig[96]) noexcept;
int fast_aggregate_verify(const std::uint8_t* pks, std::size_t n,
                          const std::uint8_t* msg, std::size_t msg_len,
                          const std::uint8_t agg_sig[96]) noexcept;

}  // namespace lux::consensus::bls
