// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// zap_vote_transport.hpp — a VoteTransport that disseminates consensus votes as
// ZAP frames over a real byte channel (a socket fd), using the canonical ZAP
// codec (luxcpp/zap-cpp-core). This is the concrete realization of the seam
// Node depends on: in production it carries votes across the validator mesh; the
// in-process Bus in the unit test is the same interface without the network.
//
// `broadcast` delivers a vote to co-located nodes AND writes it to the peer fd.
// `pump` reads one ZAP frame from the fd and delivers the decoded vote to local
// nodes. The gate dedups by voter key, so loopback echo is harmless.

#pragma once

#include "lux/consensus/node.hpp"
#include "lux/consensus/zap/vote_codec.hpp"
#include "lux/zap/wire.hpp"  // read_frame / write_frame_locked

#include <mutex>
#include <vector>

namespace lux::consensus::zap {

class ZapVoteTransport : public VoteTransport {
public:
    // `peer_fd` is one end of a connected stream socket; `local` are nodes hosted
    // on this side that should also see locally-originated and inbound votes.
    explicit ZapVoteTransport(int peer_fd, std::vector<Node *> local = {}) : fd_(peer_fd), local_(std::move(local)) {}

    // Register a co-located node (resolves the node↔transport construction cycle:
    // build the transport, construct nodes with its reference, then add them here).
    void add_local(Node * n) { local_.push_back(n); }

    void broadcast(const SignedVote & v) override {
        for (Node * n : local_)
            n->onVote(v);  // co-located delivery
        const std::vector<std::uint8_t> payload = encode_vote(v);
        lux::zap::write_frame_locked(fd_, wmu_, kVoteMsgType, payload.data(), payload.size());  // to the peer
    }

    // Read exactly one ZAP frame from the peer and deliver it to local nodes.
    // Returns false if the frame is not a vote or the read fails.
    bool pump() {
        std::uint8_t msg_type = 0;
        std::vector<std::uint8_t> payload;
        if (!lux::zap::read_frame(fd_, msg_type, payload))
            return false;
        if (lux::zap::strip_flags(msg_type) != kVoteMsgType)
            return false;
        auto v = decode_vote(payload);
        if (!v)
            return false;
        for (Node * n : local_)
            n->onVote(*v);
        return true;
    }

private:
    int fd_;
    std::mutex wmu_;
    std::vector<Node *> local_;
};

}  // namespace lux::consensus::zap
