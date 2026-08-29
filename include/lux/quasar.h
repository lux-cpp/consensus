/* Copyright (c) 2026 Lux Industries Inc.
 * SPDX-License-Identifier: BSD-3-Clause-Eco
 *
 * Quasar witness BLS verification — C ABI for the consensus hot path.
 *
 * One and only one C entry point per verb. Go's cgo bridge binds these
 * three symbols and nothing else; the C++ surface in `quasar.hpp` is the
 * implementation, not the contract.
 *
 * Wire formats are byte-identical to luxfi/consensus/protocol/quasar:
 *   - Group public key:    48-byte Zcash-compressed BLS12-381 G1
 *   - Aggregated signature: 96-byte Zcash-compressed BLS12-381 G2
 *   - Domain-separation tag: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
 *     (matches Go's `bls.Verify` via cloudflare/circl + blst with
 *      `dstSignature = ..._NUL_`). NOT the POP_ DST used by the
 *      cevm precompile path — different protocol, different DST.
 *
 * Threshold-share input layout for `lux_quasar_witness_aggregate`:
 *   N records of `(index : u32_be) || (sig : 96 bytes)` concatenated.
 *   Mirrors the wire form of luxfi/crypto/threshold/bls.SignatureShare.
 *
 * All entry points are allocation-free on the success path. Subgroup
 * checks on both points are enforced (cofactor-cleared input is
 * required for sound verification per RFC 9380 §4.1).
 *
 * Hot path: `lux_quasar_witness_verify` is the per-round verifier;
 * aggregate calls happen once per round when a fresh threshold cert is
 * assembled. Both are CPU pairings today; a future GPU backend can be
 * swapped in behind the same C ABI without recompiling Go consumers.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status enum. Negative values are reserved for future structural
 * errors (size mismatch, NULL pointer). Verify-mismatch and signature-
 * decode failure are positive so cgo callers can treat all errors as a
 * single non-OK branch and still log the specific cause. */
typedef int32_t lux_quasar_status;

#define LUX_QUASAR_OK           ((lux_quasar_status) 0)
#define LUX_QUASAR_ERR_INVALID  ((lux_quasar_status) 1) /* NULL ptr / wrong length */
#define LUX_QUASAR_ERR_SIG      ((lux_quasar_status) 2) /* sig or pk decode failed */
#define LUX_QUASAR_ERR_VERIFY   ((lux_quasar_status) 3) /* pairing rejected */

#define LUX_QUASAR_ABI_VERSION  1u

/* Exact wire widths. Mirror luxfi/crypto/bls.{PublicKey,Signature}Len. */
#define LUX_QUASAR_PK_LEN       48u
#define LUX_QUASAR_SIG_LEN      96u

/* Verify a Quasar witness: returns LUX_QUASAR_OK iff the aggregated
 * threshold signature `sig` verifies under `group_key` over `msg`.
 *
 * - group_key : 48-byte compressed G1 point (Zcash format)
 * - msg       : arbitrary-length message (may be NULL iff msg_len == 0)
 * - sig       : 96-byte compressed G2 point (Zcash format)
 *
 * Returns:
 *   LUX_QUASAR_OK           — signature verifies
 *   LUX_QUASAR_ERR_INVALID  — NULL pointer or length mismatch
 *   LUX_QUASAR_ERR_SIG      — pk or sig is not a valid curve point
 *                             (or fails subgroup check)
 *   LUX_QUASAR_ERR_VERIFY   — pairing equation does not hold
 *
 * Allocation-free in steady state. Subgroup checks on both points are
 * always performed (matches Go's `sig.SigValidate(false)` +
 * `pk.Validate()` semantics).
 */
lux_quasar_status
lux_quasar_witness_verify(const uint8_t* group_key, size_t group_key_len,
                          const uint8_t* msg,       size_t msg_len,
                          const uint8_t* sig,       size_t sig_len);

/* Aggregate `shares_n` threshold-signature shares into a single 96-byte
 * BLS aggregated signature.
 *
 * - group_key : 48-byte compressed G1 (currently unused for aggregation
 *               but preserved in the ABI so a future Lagrange-weighted
 *               aggregator can bind output to the group); pass the
 *               canonical group key to keep call sites stable.
 * - shares    : concatenation of `shares_n` records, each
 *               (index : u32 big-endian) || (sig : 96 bytes) — total
 *               size = shares_n * 100 bytes. Matches the wire format
 *               of luxfi/crypto/threshold/bls.SignatureShare.Bytes.
 * - out_sig   : 96-byte output buffer for the aggregated signature.
 *
 * Returns:
 *   LUX_QUASAR_OK           — aggregation succeeded
 *   LUX_QUASAR_ERR_INVALID  — NULL pointer / zero shares / wrong length
 *   LUX_QUASAR_ERR_SIG      — at least one share is not a valid G2
 *                             curve point (or fails subgroup check)
 *
 * Byte-identical to Go's `bls.AggregateSignatures(sigs).Compress()`
 * when shares' Lagrange coefficients reduce to identity (the n-of-n
 * case the Go aggregator takes); for t-of-n weighted aggregation the
 * caller must apply Lagrange scaling on its side before invoking this
 * function (the threshold/bls Aggregator does so in Go).
 */
lux_quasar_status
lux_quasar_witness_aggregate(const uint8_t* group_key, size_t group_key_len,
                             const uint8_t* shares,    size_t shares_n,
                             uint8_t out_sig[96]);

/* Human-readable description of a status code. Lifetime: process. */
const char* lux_quasar_status_str(lux_quasar_status s);

/* Returns LUX_QUASAR_ABI_VERSION (compile-time constant). Cgo callers
 * use this to detect ABI skew at load time. */
uint32_t lux_quasar_abi_version(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif
