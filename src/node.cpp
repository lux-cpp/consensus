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
    voted_[pos.block_id] = false;
    gate_.submit(pos);
}

Decision Node::poll(const VotePosition & pos, std::uint32_t yes, std::uint32_t total) {
    if (!positions_.count(pos.block_id)) return Decision::Undecided;
    // wave is keyed on the FULL block id (red M4) — no lossy handle.
    const Decision d = wave_.record_round(pos.block_id, yes, total);

    // Sign ONLY once wave reaches its β-confirmed ACCEPT decision — never on a
    // single transient round (red C1). A validator's BLS vote is an irrevocable
    // contribution to a >2/3-stake finality cert; it must carry the full FPC
    // confidence (β consecutive α-supermajority rounds, reset on any inconclusive
    // round), not "I saw one strong tally." This is the contract the engine's own
    // integration test asserts ("ONLY because wave decided Accept do we certify").
    if (!voted_[pos.block_id] && d == Decision::Accept) {
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
        SignedVote v;
        v.block_id = pos.block_id;
        v.voter = pk_;
        if (cevm::crypto::bls::sign(sk_.data(), msg.data(), msg.size(), v.sig.data()) == 0) {
            voted_[pos.block_id] = true;
            tx_.broadcast(v);  // disseminate; the bus echoes back, gate dedups
        }
    }
    return d;
}

VoteResult Node::onVote(const SignedVote & v) {
    return gate_.record_vote(v.block_id, v.voter, v.sig);
}

}  // namespace lux::consensus2
