// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node.hpp — one validator's view of consensus. A Node runs the liveness poll
// (wave) and the safety gate (QuorumCertEngine) over the full validator set,
// signs its own ACCEPT votes, and disseminates them through a VoteTransport.
// Independent honest nodes, each assembling from the votes they receive, converge
// on the SAME quorum certificate — that convergence is leaderless finality.
//
// The VoteTransport is the seam between consensus and the network: the in-process
// test harness implements it as a bus; a ZAP gossip layer implements it for a
// real validator mesh. consensus2 itself never knows which.

#pragma once

#include "lux/consensus2/quorum_cert_engine.hpp"
#include "lux/consensus2/wave.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace lux::consensus2 {

struct SignedVote {
    BlockId block_id{};
    PubKey voter{};
    Signature sig{};
};

// Pluggable vote dissemination. Implemented in-process for tests; by ZAP gossip
// for a real mesh. `broadcast` delivers to all peers (and may echo to the sender;
// the gate dedups by voter key, so a self-echo is harmless).
struct VoteTransport {
    virtual ~VoteTransport() = default;
    virtual void broadcast(const SignedVote & vote) = 0;
};

class Node {
public:
    // `epoch` is accepted for API symmetry; the epoch is bound per block in the
    // VotePosition's canonical message, so the Node does not store it separately.
    Node(std::uint32_t index,
         const std::array<std::uint8_t, 32> & sk,
         const PubKey & pk,
         std::vector<Validator> validator_set,
         std::uint32_t alpha,
         WaveConfig wave_cfg,
         std::uint64_t epoch,
         VoteTransport & tx);

    // Register a block this node will participate in deciding.
    void submit(const VotePosition & pos);

    // Feed one sampled poll tally. When this node's wave reaches its β-confirmed
    // ACCEPT decision it signs and broadcasts its ACCEPT vote exactly once — AND
    // only if (a) the height is not already DECIDED (mark_finalized_through) and
    // (b) it has not already committed a DIFFERENT block at this HEIGHT slot. Those
    // are the honest non-equivocation rule a BFT safety proof depends on (see
    // SlotKey below). Returns this node's wave decision.
    Decision poll(const VotePosition & pos, std::uint32_t yes, std::uint32_t total);

    // Receive a peer's signed vote into the safety gate (verified + deduped there).
    VoteResult onVote(const SignedVote & v);

    // Advance the DECIDED-HEIGHT frontier: heights <= `height` are certified/decided
    // and permanently unsignable, exactly as avalanchego's lastAcceptedHeight makes a
    // decided height's siblings unreachable. Monotonic (a lower value is ignored). The
    // caller — the finalization observer (node2 / the certifying layer) — invokes this
    // when a height is certified, mirroring Go acceptWithCertCore's prune. It (1) sets
    // the frontier so poll() refuses any height <= it (the sign gate), and (2) GCs
    // committed_slot_ entries STRICTLY BELOW `height`, retaining the tip's slot as a
    // second belt — bounding memory without ever opening a re-sign window. This is the
    // faithful mirror of the Go engine fix (prune strictly below + decided-height gate).
    //
    // DURABILITY IS THE EMBEDDER'S JOB. final_through_ is IN-MEMORY; this pure-library
    // Node has no persistence layer. To survive a restart, the embedder (node2) MUST, on
    // boot, call mark_finalized_through with its OWN persisted decided height BEFORE the
    // node signs anything — otherwise a decided-below-tip height whose slot was GC'd would
    // be re-signable across the restart (the cross-restart prune-then-resign fork). The Go
    // node is the authoritative durable path: it persists the floor in an fsync'd
    // vote-guard file and re-seeds it on boot (engine/chain vote_guard.go finalizedThrough
    // + reserveSlotForSign's decidedFloor). See proofs/no_double_finalize.tex §Slot lifecycle.
    void mark_finalized_through(std::uint64_t height);

    bool isFinal(const BlockId & b) const { return gate_.is_final(b); }
    std::optional<QuorumCert> cert(const BlockId & b) const { return gate_.assemble_cert(b); }
    bool verifyCert(const QuorumCert & c) const { return gate_.verify_cert(c); }
    std::uint32_t index() const { return index_; }

private:
    // A consensus slot is a HEIGHT — the one slot an honest validator may commit at
    // most one block to. Two distinct block ids at the same height are conflicting
    // siblings; signing ACCEPT for both is equivocation, which an honest node must
    // never do. This is the discipline the quorum-intersection safety proof relies
    // on: with every honest validator's stake in at most one quorum per height, two
    // conflicting >2/3-stake certs would have to share an intersection of >1/3
    // stake of DOUBLE-voters — necessarily Byzantine. Hence f < n/3 ⇒ no two
    // conflicting blocks finalize at one height (proofs/no_double_finalize.tex).
    //
    // WHY HEIGHT-ONLY, NOT (height, epoch): an earlier revision keyed the slot on
    // (height, epoch). That FRAGMENTS the slot — two honest sibling blocks at the SAME
    // height can carry DIFFERENT epochs (a bare/pre-fork block reports one, a wrapped
    // block another; the epoch derives from a proposer-chosen P-chain height, NOT from
    // the finalized value-chain prefix), so an honest validator could commit BOTH
    // siblings, one per (h,e) slot, and two α/⅔ certs would finalize at one height. The
    // epoch is a proposer-controlled axis and MUST NOT key the equivocation slot. It
    // still binds the SIGNED message and the cert (canonical_vote_message folds it, and
    // verify_cert re-checks the position) for anti-cross-epoch-replay — it is removed
    // ONLY from the slot. This matches the Go reference (engine/chain SlotKey{Height}).
    using SlotKey = std::uint64_t;  // height

    std::uint32_t index_;
    std::array<std::uint8_t, 32> sk_;
    PubKey pk_;
    QuorumCertEngine gate_;
    Wave wave_;
    VoteTransport & tx_;

    std::map<BlockId, VotePosition> positions_;
    // The single block this node has irrevocably ACCEPT-signed at each HEIGHT. Its
    // presence means "already voted" (idempotent re-broadcast guard); a lookup that
    // finds a DIFFERENT block id is the non-equivocation refusal. One concept: "what
    // did I commit at this height". GC'd STRICTLY BELOW the decided frontier only.
    std::map<SlotKey, BlockId> committed_slot_;
    // The decided-height frontier: every height <= this is certified and permanently
    // unsignable (the monotonic backstop that closes the prune-then-resign fork). Unset
    // until the first mark_finalized_through. IN-MEMORY only — the embedder must re-seed
    // it on boot from its persisted decided height (see mark_finalized_through). Mirrors
    // Go's decidedFloor, whose durability comes from the fsync'd vote-guard file.
    std::optional<std::uint64_t> final_through_;
};

}  // namespace lux::consensus2
