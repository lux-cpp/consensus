// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/consensus2/node.hpp"

#include "bls_signature.hpp"  // cevm::crypto::bls — REUSED signing core

namespace lux::consensus2 {

namespace {
std::uint64_t item_of(const BlockId & b) {
    std::uint64_t h = 0;
    for (int i = 0; i < 8; ++i) h = (h << 8) | b[i];
    return h;
}
}  // namespace

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
    items_[pos.block_id] = item_of(pos.block_id);
    voted_[pos.block_id] = false;
    gate_.submit(pos);
}

Decision Node::poll(const VotePosition & pos, std::uint32_t yes, std::uint32_t total) {
    const auto it = items_.find(pos.block_id);
    if (it == items_.end()) return Decision::Undecided;
    const Decision d = wave_.record_round(it->second, yes, total);

    // First time this node sees an ACCEPT supermajority, it signs and broadcasts
    // its own vote — exactly once. The epoch is bound in the position's canonical
    // message, so it is signed over without the Node tracking it separately.
    if (!voted_[pos.block_id] && static_cast<int>(yes) >= wave_.threshold()) {
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
