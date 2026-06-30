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
    // only if it has not already committed a DIFFERENT block at this (height,epoch)
    // slot. That second guard is the honest non-equivocation rule a BFT safety
    // proof depends on (see SlotKey below). Returns this node's wave decision.
    Decision poll(const VotePosition & pos, std::uint32_t yes, std::uint32_t total);

    // Receive a peer's signed vote into the safety gate (verified + deduped there).
    VoteResult onVote(const SignedVote & v);

    bool isFinal(const BlockId & b) const { return gate_.is_final(b); }
    std::optional<QuorumCert> cert(const BlockId & b) const { return gate_.assemble_cert(b); }
    bool verifyCert(const QuorumCert & c) const { return gate_.verify_cert(c); }
    std::uint32_t index() const { return index_; }

private:
    // A consensus slot — the (height, epoch) an honest validator may commit AT
    // MOST ONE block to. Two distinct block ids sharing a SlotKey are conflicting
    // siblings; signing ACCEPT for both is equivocation, which an honest node must
    // never do. This is the discipline the quorum-intersection safety proof relies
    // on: with every honest validator's stake in at most one quorum per slot, two
    // conflicting >2/3-stake certs would have to share an intersection of >1/3
    // stake of DOUBLE-voters — necessarily Byzantine. Hence f < n/3 ⇒ no two
    // conflicting blocks finalize at one height (proofs/no_double_finalize.tex).
    using SlotKey = std::pair<std::uint64_t /*height*/, std::uint64_t /*epoch*/>;

    std::uint32_t index_;
    std::array<std::uint8_t, 32> sk_;
    PubKey pk_;
    QuorumCertEngine gate_;
    Wave wave_;
    VoteTransport & tx_;

    std::map<BlockId, VotePosition> positions_;
    // The single block this node has irrevocably ACCEPT-signed at each slot. Its
    // presence means "already voted" (idempotent re-broadcast guard); a lookup
    // that finds a DIFFERENT block id is the non-equivocation refusal. One concept
    // replaces the old per-block_id `voted_` flag: "what did I commit at this slot".
    std::map<SlotKey, BlockId> committed_slot_;
};

}  // namespace lux::consensus2
