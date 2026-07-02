// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/consensus2/node.hpp"

#include "bls_signature.hpp"  // cevm::crypto::bls — REUSED signing core

namespace lux::consensus2 {

Node::Node(std::uint32_t index,
           const std::array<std::uint8_t, 32> & sk,
           const PubKey & pk,
           std::vector<Validator> validator_set,
           std::uint32_t alpha,
           WaveConfig wave_cfg,
           std::uint64_t /*epoch*/,
           VoteTransport & tx)
    : index_(index), sk_(sk), pk_(pk),
      gate_(std::move(validator_set), alpha), wave_(wave_cfg), tx_(tx) {}

void Node::submit(const VotePosition & pos) {
    if (positions_.count(pos.block_id)) return;
    positions_[pos.block_id] = pos;
    gate_.submit(pos);
}

Decision Node::poll(const VotePosition & pos, std::uint32_t yes, std::uint32_t total) {
    if (!positions_.count(pos.block_id)) return Decision::Undecided;
    // wave is keyed on the FULL block id (red M4) — no lossy handle.
    const Decision d = wave_.record_round(pos.block_id, yes, total);
    if (d != Decision::Accept) return d;

    // THREE guards gate the irrevocable ACCEPT signature:
    //
    //  (1) β-confirmation (red C1): we sign only on the wave's β-confirmed ACCEPT
    //      decision, never on a single transient round. A BLS vote is an
    //      irrevocable contribution to a >2/3-stake finality cert; it must carry
    //      full FPC confidence (β consecutive α-supermajority rounds, reset on any
    //      inconclusive round). The `d == Accept` above is that decision.
    //
    //  (2) DECIDED-HEIGHT GATE (the monotonic backstop): a height at or below the
    //      decided frontier is settled — exactly one block was certified there and its
    //      every sibling is permanently unsignable, as avalanchego's
    //      acceptPreferredChild+rejectTransitively makes a decided height's siblings
    //      unreachable and drops their votes. Never sign at a decided height. This
    //      closes the prune-then-resign fork: even after a height's slot is GC'd, a
    //      late/differently-enveloped sibling there can never collect this node's
    //      SECOND signature. Mirrors Go reserveSlotForSign's decided-floor check.
    //      NOTE: final_through_ is IN-MEMORY; durability across a restart is the
    //      embedder's responsibility — node2 must re-seed it via mark_finalized_through
    //      from its persisted decided height on boot (the Go node persists it in the
    //      fsync'd vote-guard file). See node.hpp / no_double_finalize.tex.
    //
    //  (3) NON-EQUIVOCATION (per-height slot): an honest validator commits AT MOST
    //      ONE block per HEIGHT. If we already ACCEPT-signed a DIFFERENT block at
    //      this height, REFUSE this sibling — signing both would place this node's
    //      stake in two conflicting quorums and break the quorum-intersection
    //      argument that gives f < n/3 safety (proofs/no_double_finalize.tex). If we
    //      already signed THIS block, the re-broadcast is suppressed (idempotent).
    if (final_through_ && pos.height <= *final_through_) return d;  // (2) decided height

    const SlotKey slot = pos.height;
    const auto it = committed_slot_.find(slot);
    if (it != committed_slot_.end()) return d;  // (3) already committed at this height
                                                 // (same block: idempotent; sibling: refused)

    const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
    SignedVote v;
    v.block_id = pos.block_id;
    v.voter = pk_;
    if (cevm::crypto::bls::sign(sk_.data(), msg.data(), msg.size(), v.sig.data()) == 0) {
        committed_slot_.emplace(slot, pos.block_id);  // bind this height to this block
        tx_.broadcast(v);  // disseminate; the bus echoes back, gate dedups
    }
    return d;
}

void Node::mark_finalized_through(std::uint64_t height) {
    // Monotonic: a stale/lower frontier never regresses the decided frontier.
    if (final_through_ && height <= *final_through_) return;
    final_through_ = height;
    // GC committed_slot_ STRICTLY BELOW the frontier — retain the tip's slot as an
    // in-memory belt (the decided-height gate covers the frontier itself durably).
    // Strictly-below is essential: an inclusive erase would delete the just-decided
    // height's slot, and without the gate that reopened the prune-then-resign fork.
    for (auto it = committed_slot_.begin(); it != committed_slot_.end();) {
        if (it->first < height) it = committed_slot_.erase(it);
        else ++it;
    }
}

VoteResult Node::onVote(const SignedVote & v) {
    return gate_.record_vote(v.block_id, v.voter, v.sig);
}

}  // namespace lux::consensus2
