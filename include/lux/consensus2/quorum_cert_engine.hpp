// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// quorum_cert_engine.hpp — the finality GATE of consensus2, in pure C++.
//
// THE FINALITY RULE (one rule, one place), ported from the Go reference
// engine/chain/cert.go:
//
//   A block finalizes at a TIER only after that tier's floor of DISTINCT
//   validators have each produced a correctly-BLS-signed ACCEPT vote over the
//   SAME canonical position, AND the summed stake of those distinct voters
//   strictly exceeds the tier's stake floor:
//
//     Nova   (local execution) — voters ≥ nova_signer_floor(n)
//                                stake  > half_stake_floor(total)
//     Quasar (export)          — voters ≥ α
//                                stake  > two_thirds_stake_floor(total)
//
//   Nova is crash-fault-safe and reorgable; only Quasar authorizes export
//   (bridges, DEX settlement, cross-chain). Go engine/chain VerifyWeighted.
//
// DECOMPLECTION — three orthogonal concerns, never braided:
//   1. THE RULE   — "tier floor of distinct voters AND tier stake floor,
//                    fail-closed" lives in QuorumCertEngine::meets_quorum /
//                    verify_cert. Pure logic.
//   2. THE CRYPTO — per-validator BLS12-381 verify is lux::consensus2::bls,
//                    the Lux consensus vote domain over blst (bls.hpp). The
//                    engine never invents a signature scheme; it CALLS one.
//   3. THE MESSAGE— canonical_vote_message() is a deterministic, domain-
//                    separated function of the position and the decision. A
//                    signature for one position/decision can never be replayed
//                    at another. Byte-identical to the Go encoder.
//
// This is a quorum CERTIFICATE, not threshold signing: each validator holds a
// DISTINCT key and signs individually; nothing combines secret shares. Building
// a cert needs no secrets — any node that collected a tier's quorum of distinct
// valid ACCEPT votes assembles the identical cert (leaderless, permissionless).
// The aggregate signature is a post-hoc BLS aggregation of the already-verified
// per-voter signatures, re-verifiable by any holder of the validator set.
//
// SCOPE: this is the finality GATE. Snow sampling / re-poll live in wave.hpp and
// photon.hpp; equivocation is the Node's slot discipline; the PQ Corona / Pulsar
// / Magnetar legs (ML-DSA / Ringtail) are not here. The rule above does not
// change when they arrive.

#pragma once

#include "lux/consensus2/threshold.hpp"  // the tier floors — one definition, shared with wave

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

namespace lux::consensus2 {

// ── Wire constants, bound into every signed message (non-malleable role/version)
inline constexpr std::uint16_t kQuorumCertVersion = 3;  // Go chain.QuorumCertVersion
inline constexpr std::uint8_t  kQCFinality        = 1;  // Go chain.QCFinality

// ── Fixed-width identifiers and crypto material
using Id        = std::array<std::uint8_t, 32>;  // Go ids.ID
using BlockId   = Id;                            // a block's transport identity
using PubKey    = std::array<std::uint8_t, 48>;  // compressed G1 public key
using Signature = std::array<std::uint8_t, 96>;  // compressed G2 signature

// The all-zero id — Go ids.Empty. The canonical-degrade sentinel.
inline constexpr Id kEmptyId{};

// The finality rung a cert attests. Values are Go engine/chain.Finality's, so a
// tier crossing the wire means the same number on both sides.
//   Photon=0 / Wave=1 are pre-finality sampling states and never label a cert.
enum class Tier : std::uint8_t {
    Nova   = 2,  // bare-majority local-execution cert; authorizes NO export
    Quasar = 3,  // strict ⅔-by-stake export cert
};

// A validator is a distinct {public key, voting stake}. Stake must be > 0 for an
// in-set validator; an out-of-set key contributes 0 stake (cannot inflate a tally).
struct Validator {
    PubKey        pubkey;
    std::uint64_t stake;
};

// The consensus position a vote (and a cert) binds to — the Go
// engine/chain.VotePosition axes, one for one.
//
// THE CANONICAL / TRANSPORT SPLIT. A block carries two identities:
//
//   - the CANONICAL execution identity {canonical_id, parent_canonical_id,
//     execution_state_root, payload_root}. This is the primary consensus object.
//     Finality certifies it, the per-height equivocation slot keys on it, and it
//     is folded into the signed message — so a signature is bound to the exact
//     execution result.
//   - the TRANSPORT identity {block_id, parent_id} — the outer proposervm
//     envelope ids. A cache key for block lookup and gossip only. They are NOT
//     in the signed message, so two different outer envelopes wrapping the same
//     inner block sign identical messages: their votes interoperate and their
//     certs are duplicate aliases, never a fork.
//
// A block with no inner/outer split leaves the canonical axes empty and degrades
// to canonical == transport; canonical_id_of / parent_canonical_id_of resolve
// that in ONE place so every producer of a position signs the same bytes.
struct VotePosition {
    Id            chain_id{};
    std::uint64_t height = 0;
    std::uint32_t round  = 0;

    // Transport identity — NOT signed.
    Id block_id{};
    Id parent_id{};

    // Canonical execution identity — signed.
    Id canonical_id{};
    Id parent_canonical_id{};
    Id execution_state_root{};
    Id payload_root{};

    // Binds the vote to the exact weighted validator set it was cast under, so a
    // cross-epoch stake change cannot retroactively re-present a cert under a
    // different set. Empty means "no set-root bound", signed consistently as such.
    Id validator_set_root{};
};

// The canonical execution identity of a position, with the Go degrade applied:
// an unset canonical axis falls back to its transport sibling. ONE definition —
// the signed message and the equivocation slot both read it here.
[[nodiscard]] Id canonical_id_of(const VotePosition& pos) noexcept;
[[nodiscard]] Id parent_canonical_id_of(const VotePosition& pos) noexcept;

// The exact byte string a validator signs for a position and a decision.
// Deterministic, fixed-width, big-endian, length-free — byte-identical to Go
// engine/chain.canonicalVoteMessageFor:
//
//   "LUX/chain/vote/v2\0"  version:2  qc_type:1
//   chain_id:32  height:8  round:4
//   canonical_block_id:32  parent_canonical_id:32
//   execution_state_root:32  payload_root:32  validator_set_root:32
//   accept:1        (0x01 accept | 0x00 reject)
//
// 226 bytes. The accept byte is bound, so an ACCEPT signature (what a cert
// carries) and a REJECT signature over the same position are DISTINCT messages.
// The domain tag, version and qc_type make a signature un-liftable to another
// protocol, version or role.
[[nodiscard]] std::vector<std::uint8_t> canonical_vote_message(const VotePosition& pos,
                                                               bool accept = true);

// Outcome of offering one vote to the gate.
//
// Recorded does NOT mean verified. A vote joins the tally as a CANDIDATE with no
// per-vote pairing; the whole tally is verified in ONE aggregate pairing when the
// GATE is asked (is_final / assemble_cert), and a forged candidate is evicted
// there. Finality requires that verification, so an unverified vote can never
// move the gate — but the enum must not promise a check that has not run yet.
// Once a block's tally has been verified, every further vote is individually
// verified before it joins, and RejectedBadSignature is then reported per vote.
enum class VoteResult {
    Recorded,                 // new DISTINCT voter joined the tally
    Duplicate,                // validator already recorded — a replay counts ONCE
    RejectedBadSignature,     // BLS verify failed — NOT counted (forgery defense)
    RejectedUnknownValidator, // pubkey not in the validator set — NOT counted
    RejectedNoSuchBlock,      // submit() was never called for this block
};

// Portable finality witness: the tier's floor of distinct validators each signed
// ACCEPT over Position, and their summed stake clears the tier's stake floor.
// Verifiable by any holder of the validator set via QuorumCertEngine::verify_cert,
// independent of live engine state (gossipable). aggregate_sig is the BLS
// aggregation of the per-voter ACCEPT signatures over the common canonical message.
struct QuorumCert {
    std::uint16_t          version;        // == kQuorumCertVersion
    std::uint8_t           type;           // == kQCFinality
    Tier                   tier;           // Nova (accept) or Quasar (export)
    VotePosition           position;
    std::uint32_t          threshold;      // the tier's distinct-voter floor
    std::vector<PubKey>    voters;          // sorted strictly-ascending, distinct
    Signature              aggregate_sig;   // Σ per-voter G2 signatures
    std::uint64_t          voted_stake;     // Σ stake of voters (informational)
    std::uint64_t          total_stake;     // engine total at assembly (informational)
};

// QuorumCertEngine — collects per-validator ACCEPT votes for pending blocks and
// answers the finality gate. One engine instance per validator set / epoch (a set
// rotation constructs a fresh engine, mirroring Go's NewVerifier discipline).
class QuorumCertEngine {
public:
    // Construct with a validator set and the Quasar distinct-voter floor α. Fail
    // loud at the system boundary (throws std::invalid_argument) on
    // misconfiguration: empty set, α == 0, α > validator count (unreachable
    // quorum), a duplicate pubkey, or an in-set validator with 0 stake.
    QuorumCertEngine(std::vector<Validator> validators, std::uint32_t alpha);

    // Register a pending block to collect votes for. Returns false if a block with
    // this id is already pending (idempotent guard).
    bool submit(const VotePosition& pos);

    // The registered position for a pending block, or nullopt. The AUTHORITATIVE
    // position: what a vote is signed over is what submit() registered, never what
    // a later caller passes alongside the block id.
    [[nodiscard]] std::optional<VotePosition> position(const BlockId& block_id) const;

    // Offer one validator's ACCEPT vote. Rejects out-of-set keys and dedups by
    // validator key so a replay counts once. See VoteResult on when the BLS check
    // runs.
    [[nodiscard]] VoteResult record_vote(const BlockId& block_id,
                                         const PubKey& voter,
                                         const Signature& sig);

    // THE GATE. true IFF (total_stake>0) AND a BLS check covering every counted
    // voter has passed AND (distinct voters ≥ the tier's signer floor) AND
    // (summed stake > the tier's stake floor). No force-accept, no k==1, no
    // count-only path; fail-closed on a missing block or zero total stake.
    [[nodiscard]] bool is_final(const BlockId& block_id, Tier tier = Tier::Quasar) const;

    // Assemble the portable witness for a block final AT `tier` (else nullopt).
    [[nodiscard]] std::optional<QuorumCert> assemble_cert(const BlockId& block_id,
                                                          Tier tier = Tier::Quasar) const;

    // Independently re-verify a cert against this engine's validator set: version,
    // type, tier, strictly-increasing distinct in-set voters, the tier's signer and
    // stake floors recomputed from the AUTHORITATIVE set (never trusted from the
    // cert), and the aggregate BLS signature over the canonical message. Does NOT
    // consult live pending state — a pure witness check. A Nova cert relabelled
    // Quasar fails the ⅔ stake clause; a Quasar cert relabelled Nova only
    // under-claims.
    [[nodiscard]] bool verify_cert(const QuorumCert& cert) const;

    // Drop a block's accumulated votes once the caller has committed it. Without
    // this the engine retains every finalized block's vote set forever. Idempotent;
    // returns true if a block was removed.
    bool drop(const BlockId& block_id);

    // ── Introspection (tests / observability)
    [[nodiscard]] std::uint32_t alpha() const noexcept { return alpha_; }
    [[nodiscard]] std::uint64_t total_stake() const noexcept { return total_stake_; }
    [[nodiscard]] std::uint32_t validator_count() const noexcept {
        return static_cast<std::uint32_t>(validators_.size());
    }
    // The distinct-voter floor for a tier under THIS validator set.
    [[nodiscard]] std::uint32_t signer_floor(Tier tier) const noexcept;
    // The stake a tally must STRICTLY exceed for a tier under this set.
    [[nodiscard]] std::uint64_t stake_floor(Tier tier) const noexcept;
    [[nodiscard]] std::size_t   distinct_voters(const BlockId& block_id) const;
    [[nodiscard]] std::uint64_t voted_stake(const BlockId& block_id) const;

private:
    // One pending block's accumulated state.
    struct Pending {
        VotePosition                 pos;
        std::vector<std::uint8_t>    message;       // cached canonical ACCEPT message
        std::map<PubKey, Signature>  votes;         // dedup by key; sigs (see `verified`)
        std::uint64_t                voted_stake = 0;
        // BATCH VERIFY: votes join WITHOUT a per-vote pairing (m individual verifies
        // cost ~m×; one aggregate verify is ~1×). The aggregate runs ONCE, when the
        // gate is asked and the asked tier's floors are cleared — so a node pays one
        // pairing per block at the tier it actually consumes, and the engine never has
        // to guess which tier that is. `verified` is set only after a BLS check
        // covering EVERY counted voter has passed (the aggregate, or the
        // individual-verify eviction fallback, after which every survivor is checked).
        // Finality requires it, so an unverified sig can never drive finality. After
        // `verified`, any further vote is individually verified before it joins.
        bool                         verified = false;
    };

    // Resolve a voter's stake; 0 for an out-of-set key (cannot inflate a tally),
    // matching Go StakeSource.Weight semantics.
    [[nodiscard]] std::uint64_t stake_of(const PubKey& voter) const;

    // The count/stake floors of a tier are met by this tally (verification aside).
    [[nodiscard]] bool clears_floors(const Pending& p, Tier tier) const noexcept;

    // Aggregate every stored sig and fast_aggregate_verify it over the cached
    // message under the aggregate of the voters' pubkeys. One pairing, not m.
    [[nodiscard]] bool batch_verify(const Pending& p) const;

    // Establish the "every counted voter is verified" invariant, once. The aggregate
    // pairing first; if it fails a forged sig is present, so fall back to individual
    // verifies, erase the invalid ones and refund their stake. Either way every
    // survivor is verified when this returns, so it never runs twice for one tally.
    void verify_tally(Pending& p) const;

    // THE GATE on an already-resolved Pending — assumes mu_ is held. Verifies the
    // tally on first demand, then requires the tier's floors (re-checked, because a
    // forged-sig eviction can drop a tally back below them).
    [[nodiscard]] bool meets_quorum(Pending& p, Tier tier) const;

    std::map<PubKey, std::uint64_t> validators_;   // pubkey → stake (sorted, distinct)
    std::uint64_t                   total_stake_;   // Σ in-set stake
    std::uint32_t                   alpha_;         // Quasar distinct-voter floor
    // mutable: the gate VERIFIES on demand (verify_tally memoizes into Pending), so
    // is_final/assemble_cert stay logically const observations while doing the one
    // pairing the answer needs. All access is under mu_.
    mutable std::map<BlockId, Pending> pending_;    // block → accumulated votes

    // Serializes all access to mutable pending_ state. The production gossip mesh
    // delivers votes from multiple reader threads (one per peer); without this the
    // receive path is a data race. validators_/total_stake_/alpha_ are immutable
    // after construction, so verify_cert reads them lock-free.
    mutable std::mutex mu_;
};

}  // namespace lux::consensus2
