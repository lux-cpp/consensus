// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// quorum_cert_engine.hpp — the finality GATE of consensus2, in pure C++.
//
// THE FINALITY RULE (one rule, one place), ported from the Go reference
// engine/chain/quorum_cert.go:
//
//   A block FINALIZES only after α DISTINCT validators have each produced a
//   correctly-BLS-signed ACCEPT vote over the SAME canonical position
//   (block_id, height, epoch) AND the summed stake of those distinct voters is
//   a STRICT two-thirds supermajority: voted > floor(2/3 · total_stake).
//
// DECOMPLECTION — three orthogonal concerns, never braided:
//   1. THE RULE   — "α distinct voters AND >2/3 stake, fail-closed" lives in
//                    QuorumCertEngine::is_final / verify_cert. Pure logic.
//   2. THE CRYPTO — per-validator BLS12-381 verify is the cevm::crypto::bls
//                    primitive (blst-backed, IRTF POP ciphersuite). The engine
//                    never invents a signature scheme; it CALLS a proven one.
//   3. THE MESSAGE— canonical_vote_message() is a deterministic, domain-
//                    separated function of the position. A signature for one
//                    (block,height,epoch,accept) can never be replayed at
//                    another.
//
// This is a quorum CERTIFICATE, not threshold signing: each validator holds a
// DISTINCT key and signs individually; nothing combines secret shares. Building
// a cert needs no secrets — any node that collected α distinct valid ACCEPT
// votes assembles the identical cert (leaderless, permissionless). The optional
// aggregate signature is a post-hoc BLS aggregation of the already-verified
// per-voter signatures, re-verifiable by any holder of the validator set.
//
// WHAT THE TOY STUB (pkg/c) GETS WRONG AND THIS DOES NOT:
//   - dedup by validator key: a replayed/duplicate vote counts ONCE, so one
//     validator can never manufacture a quorum by repeating itself.
//   - stake supermajority: a count of α voters is NOT finality on its own; the
//     summed STAKE must strictly exceed 2/3 — a coalition of many low-stake
//     validators reaching the count but not the stake does NOT finalize.
//   - fail-closed: total_stake==0 (or no validator set) NEVER finalizes; there
//     is no ForceAccept / k==1 / count-only path anywhere.
//
// SCOPE (seed): this is the finality GATE only. Snow sampling / re-poll,
// equivocation slashing, the PQ Corona/Pulsar/Magnetar legs (ML-DSA/Ringtail),
// and networking are OUT of scope and arrive in later phases. The position here
// is (block_id,height,epoch); the full Go position axes (chain/round/parent/
// validator-set-root) and pluggable non-BLS lanes land when the gate grows into
// the full engine — the rule above does not change.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

namespace lux::consensus2 {

// ── Wire constants, bound into every signed message (non-malleable role/version)
inline constexpr std::uint16_t kQuorumCertVersion = 2;  // mirrors Go QuorumCertVersion
inline constexpr std::uint8_t  kQCFinality        = 1;  // mirrors Go QCFinality

// ── Fixed-width crypto material (compressed BLS12-381, eth2 "min-pubkey" scheme)
using BlockId   = std::array<std::uint8_t, 32>;  // 32-byte block identifier
using PubKey    = std::array<std::uint8_t, 48>;  // compressed G1 public key
using Signature = std::array<std::uint8_t, 96>;  // compressed G2 signature

// A validator is a distinct {public key, voting stake}. Stake must be > 0 for an
// in-set validator; an out-of-set key contributes 0 stake (cannot inflate a tally).
struct Validator {
    PubKey        pubkey;
    std::uint64_t stake;
};

// The consensus position a vote (and a cert) binds to. Every axis is folded into
// the canonical signed message, so a signature for one position can never be
// presented at another.
struct VotePosition {
    BlockId       block_id;
    std::uint64_t height;
    std::uint64_t epoch;
};

// floor(2·total/3), computed without overflow — byte-identical to the Go
// reference config.TwoThirdsStakeFloor. total = 3q+r ⇒ floor = 2q + (r==2?1:0).
// The STRICT supermajority predicate is voted > two_thirds_stake_floor(total).
[[nodiscard]] std::uint64_t two_thirds_stake_floor(std::uint64_t total) noexcept;

// The exact byte string a validator signs to ACCEPT a position. Deterministic and
// domain-separated:
//   "LUX/chain/vote/v1\0"  version:2(BE)  qc_type:1  block_id:32
//   height:8(BE)  epoch:8(BE)  accept:1(=0x01)
// The domain tag + version + qc_type + accept byte make a signature un-liftable to
// a different protocol, version, role, or decision (anti-replay), matching the Go
// canonicalVoteMessageFor discipline.
[[nodiscard]] std::vector<std::uint8_t> canonical_vote_message(const VotePosition& pos);

// Outcome of offering one vote. Only Accepted moves the finality needle; every
// other variant leaves distinct-voter count and summed stake untouched.
enum class VoteResult {
    Accepted,                 // BLS sig verified; new DISTINCT voter recorded
    Duplicate,                // validator already recorded — replay counts ONCE
    RejectedBadSignature,     // BLS verify failed — NOT counted (forgery defense)
    RejectedUnknownValidator, // pubkey not in the validator set — NOT counted
    RejectedNoSuchBlock,      // submit() was never called for this block
};

// Portable finality witness: α distinct validators each signed ACCEPT over
// Position, and their summed stake is a strict >2/3 supermajority. Verifiable by
// any holder of the validator set via QuorumCertEngine::verify_cert, independent
// of live engine state (gossipable). aggregate_sig is the BLS aggregation of the
// per-voter ACCEPT signatures over the common canonical message.
struct QuorumCert {
    std::uint16_t          version;       // == kQuorumCertVersion
    std::uint8_t           type;          // == kQCFinality
    VotePosition           position;
    std::uint32_t          threshold;     // α — distinct-voter floor
    std::vector<PubKey>    voters;         // sorted strictly-ascending, distinct
    Signature              aggregate_sig;  // Σ per-voter G2 signatures
    std::uint64_t          voted_stake;    // Σ stake of voters (informational)
    std::uint64_t          total_stake;    // engine total at assembly (informational)
};

// QuorumCertEngine — collects per-validator ACCEPT votes for pending blocks and
// answers the finality gate. One engine instance per validator set / epoch (a set
// rotation constructs a fresh engine, mirroring Go's NewVerifier discipline).
class QuorumCertEngine {
public:
    // Construct with a validator set and the distinct-voter floor α. Fail-loud at
    // the system boundary (throws std::invalid_argument) on misconfiguration:
    //   - empty validator set, or α == 0, or α > validator count (unreachable
    //     quorum), or a duplicate pubkey, or an in-set validator with 0 stake.
    QuorumCertEngine(std::vector<Validator> validators, std::uint32_t alpha);

    // Register a pending block to collect votes for. Returns false if a block with
    // this id is already pending (idempotent guard). Idempotent positions only.
    bool submit(const VotePosition& pos);

    // Offer one validator's ACCEPT vote. Verifies the BLS signature over the
    // pending block's canonical message; rejects bad sigs and out-of-set keys;
    // dedups by validator key so a replay counts once. See VoteResult.
    [[nodiscard]] VoteResult record_vote(const BlockId& block_id,
                                         const PubKey& voter,
                                         const Signature& sig);

    // THE GATE. true IFF (total_stake>0) AND (distinct voters ≥ α) AND
    // (summed stake > floor(2/3·total_stake)). No ForceAccept, no k==1, no
    // count-only path; fail-closed on a missing block or zero total stake.
    [[nodiscard]] bool is_final(const BlockId& block_id) const;

    // Assemble the portable finality witness for a FINAL block (else nullopt).
    // Aggregates the verified per-voter signatures into one cert.
    [[nodiscard]] std::optional<QuorumCert> assemble_cert(const BlockId& block_id) const;

    // Independently re-verify a cert against this engine's validator set: version/
    // type/threshold, strictly-increasing distinct in-set voters, α floor, strict
    // 2/3 stake, AND the aggregate BLS signature over the canonical message. Does
    // NOT consult live pending state — a pure witness check.
    [[nodiscard]] bool verify_cert(const QuorumCert& cert) const;

    // Drop a block's accumulated votes once the caller has committed it (assembled
    // its cert). Without this the engine retains every finalized block's vote set
    // forever — unbounded memory, and an O(N) scan for any caller that re-walks
    // pending_. Idempotent; returns true if a block was removed.
    bool drop(const BlockId& block_id);

    // ── Introspection (tests / observability)
    [[nodiscard]] std::uint32_t alpha() const noexcept { return alpha_; }
    [[nodiscard]] std::uint64_t total_stake() const noexcept { return total_stake_; }
    [[nodiscard]] std::size_t   distinct_voters(const BlockId& block_id) const;
    [[nodiscard]] std::uint64_t voted_stake(const BlockId& block_id) const;

private:
    // One pending block's accumulated state.
    struct Pending {
        VotePosition                 pos;
        std::vector<std::uint8_t>    message;       // cached canonical message
        std::map<PubKey, Signature>  votes;         // dedup by key; verified sigs only
        std::uint64_t                voted_stake = 0;
    };

    // Resolve a voter's stake; returns 0 for an out-of-set key (cannot inflate a
    // tally), matching Go StakeSource.Weight semantics.
    [[nodiscard]] std::uint64_t stake_of(const PubKey& voter) const;

    // THE GATE on an already-resolved Pending — assumes mu_ is held. Factored out
    // so is_final and assemble_cert each take mu_ exactly once (no re-entrant lock).
    [[nodiscard]] bool meets_quorum(const Pending& p) const noexcept;

    std::map<PubKey, std::uint64_t> validators_;   // pubkey → stake (sorted, distinct)
    std::uint64_t                   total_stake_;   // Σ in-set stake
    std::uint32_t                   alpha_;         // distinct-voter floor
    std::map<BlockId, Pending>      pending_;       // block → accumulated votes

    // Serializes all access to mutable pending_ state. The production gossip mesh
    // delivers votes from multiple reader threads (one per peer); without this the
    // receive path is a data race (red M1, TSan-proven). validators_/total_stake_/
    // alpha_ are immutable after construction, so verify_cert reads them lock-free.
    mutable std::mutex mu_;
};

}  // namespace lux::consensus2
