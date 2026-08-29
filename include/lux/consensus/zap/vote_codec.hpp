// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// vote_codec.hpp — ZAP wire codec for a consensus SignedVote. Encodes/decodes a
// vote as a ZAP frame payload (lux::zap::Writer/Reader), so votes ride the
// canonical Lux ZAP transport (luxcpp/zap-cpp-core) between validators. This is
// the adapter layer: core consensus has no ZAP dependency; only this header and
// the ZapVoteTransport do.

#pragma once

#include "lux/consensus/node.hpp"  // SignedVote
#include "lux/zap/wire.hpp"          // lux::zap::Writer / Reader

#include <cstdint>
#include <optional>
#include <vector>

namespace lux::consensus::zap {

// ZAP MsgType id for a gossiped consensus vote (lower 6 bits, per ZAP spec).
constexpr std::uint8_t kVoteMsgType = 0x11;

// Encode: block_id(32) ‖ voter pubkey(48) ‖ signature(96), each length-framed by
// the ZAP Writer. Returns the frame payload (the msg_type byte + frame length are
// added by write_frame on send).
inline std::vector<std::uint8_t> encode_vote(const SignedVote & v) {
    lux::zap::Writer w;
    w.write_bytes(v.block_id.data(), v.block_id.size());
    w.write_bytes(v.voter.data(), v.voter.size());
    w.write_bytes(v.sig.data(), v.sig.size());
    return w.take();
}

// Decode a vote from a ZAP frame payload. Returns nullopt on any malformed field
// (wrong length, truncation) — a peer cannot inject a structurally invalid vote.
inline std::optional<SignedVote> decode_vote(const std::vector<std::uint8_t> & payload) {
    lux::zap::Reader r(payload.data(), payload.size());
    std::vector<std::uint8_t> block_id, voter, sig;
    if (!r.read_bytes(block_id) || !r.read_bytes(voter) || !r.read_bytes(sig))
        return std::nullopt;
    if (block_id.size() != 32 || voter.size() != 48 || sig.size() != 96)
        return std::nullopt;
    // Canonical framing: reject any trailing bytes after the three fixed fields, so
    // `vote ‖ garbage` cannot decode to a valid vote (red L6, wire non-malleability).
    if (r.remaining() != 0)
        return std::nullopt;
    SignedVote v;
    for (std::size_t i = 0; i < 32; ++i) v.block_id[i] = block_id[i];
    for (std::size_t i = 0; i < 48; ++i) v.voter[i] = voter[i];
    for (std::size_t i = 0; i < 96; ++i) v.sig[i] = sig[i];
    return v;
}

}  // namespace lux::consensus::zap
