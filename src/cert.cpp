// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// cert.cpp — the portable finality certificate. See cert.hpp for why C++ has
// two certificate types and which one this is.

#include "lux/consensus/cert.hpp"

#include "lux/consensus/bls.hpp"

#include <blst.h>

#include <cstring>

namespace lux::consensus {

const char* refusal_name(Refusal r) noexcept {
    switch (r) {
        case Refusal::None:           return "ok";
        case Refusal::Version:        return "version";
        case Refusal::Role:           return "role";
        case Refusal::Tier:           return "tier";
        case Refusal::ThresholdZero:  return "threshold_zero";
        case Refusal::NoVotes:        return "no_votes";
        case Refusal::Order:          return "order";
        case Refusal::NotAccept:      return "not_accept";
        case Refusal::Signature:      return "signature";
        case Refusal::BelowThreshold: return "below_threshold";
        case Refusal::Wire:           return "wire";
    }
    return "unknown";
}

namespace {

void put16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(std::uint8_t(v >> 8));
    b.push_back(std::uint8_t(v));
}
void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
}
void put64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
}
void putid(std::vector<std::uint8_t>& b, const Id& id) { b.insert(b.end(), id.begin(), id.end()); }

// A cursor that cannot read past its buffer. Every accessor reports failure
// rather than returning something it did not read.
class Cursor {
public:
    Cursor(const std::uint8_t* data, std::size_t len) : d_(data), n_(len) {}

    bool u8(std::uint8_t& out) {
        if (n_ - at_ < 1) return false;
        out = d_[at_++];
        return true;
    }
    bool u16(std::uint16_t& out) {
        if (n_ - at_ < 2) return false;
        out = std::uint16_t(std::uint16_t(d_[at_]) << 8 | d_[at_ + 1]);
        at_ += 2;
        return true;
    }
    bool u32(std::uint32_t& out) {
        if (n_ - at_ < 4) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) out = std::uint32_t(out << 8) | d_[at_ + std::size_t(i)];
        at_ += 4;
        return true;
    }
    bool u64(std::uint64_t& out) {
        if (n_ - at_ < 8) return false;
        out = 0;
        for (int i = 0; i < 8; ++i) out = std::uint64_t(out << 8) | d_[at_ + std::size_t(i)];
        at_ += 8;
        return true;
    }
    template <std::size_t N>
    bool fixed(std::array<std::uint8_t, N>& out) {
        if (n_ - at_ < N) return false;
        std::memcpy(out.data(), d_ + at_, N);
        at_ += N;
        return true;
    }
    bool take(std::size_t len, std::vector<std::uint8_t>& out) {
        if (n_ - at_ < len) return false;
        out.assign(d_ + at_, d_ + at_ + len);
        at_ += len;
        return true;
    }

    [[nodiscard]] std::size_t left() const noexcept { return n_ - at_; }
    [[nodiscard]] bool done() const noexcept { return at_ == n_; }

private:
    const std::uint8_t* d_;
    std::size_t         n_;
    std::size_t         at_ = 0;
};

}  // namespace

std::vector<std::uint8_t> Cert::encode() const {
    std::vector<std::uint8_t> b;
    b.reserve(kCertHeaderLen + votes.size() * (kCertVoteFixedLen + 96));
    put16(b, version);
    b.push_back(role);
    b.push_back(static_cast<std::uint8_t>(tier));
    putid(b, position.chain_id);
    put64(b, position.height);
    put32(b, position.round);
    putid(b, position.block_id);
    putid(b, position.parent_id);
    putid(b, position.canonical_id);
    putid(b, position.parent_canonical_id);
    putid(b, position.execution_state_root);
    putid(b, position.payload_root);
    putid(b, position.validator_set_root);
    put32(b, threshold);
    put32(b, static_cast<std::uint32_t>(votes.size()));
    for (const Vote& v : votes) {
        b.insert(b.end(), v.node.begin(), v.node.end());
        b.push_back(v.accept ? 0x01 : 0x00);
        put32(b, static_cast<std::uint32_t>(v.signature.size()));
        b.insert(b.end(), v.signature.begin(), v.signature.end());
    }
    return b;
}

std::optional<Cert> Cert::decode(const std::uint8_t* data, std::size_t len, Refusal& why) {
    why = Refusal::Wire;
    Cursor c(data, len);
    Cert cert;

    std::uint8_t tier_byte = 0;
    if (!c.u16(cert.version)) return std::nullopt;
    if (!c.u8(cert.role)) return std::nullopt;
    if (!c.u8(tier_byte)) return std::nullopt;
    // The tier byte is CARRIED, not judged, exactly as Go's decoder carries it:
    // a rung outside the ladder is a Verify refusal, not a wire refusal, so the
    // two implementations report the same clause for the same bytes. Tier's
    // underlying type is uint8_t, so every byte is representable.
    cert.tier = static_cast<Tier>(tier_byte);

    if (!c.fixed(cert.position.chain_id)) return std::nullopt;
    if (!c.u64(cert.position.height)) return std::nullopt;
    if (!c.u32(cert.position.round)) return std::nullopt;
    if (!c.fixed(cert.position.block_id)) return std::nullopt;
    if (!c.fixed(cert.position.parent_id)) return std::nullopt;
    if (!c.fixed(cert.position.canonical_id)) return std::nullopt;
    if (!c.fixed(cert.position.parent_canonical_id)) return std::nullopt;
    if (!c.fixed(cert.position.execution_state_root)) return std::nullopt;
    if (!c.fixed(cert.position.payload_root)) return std::nullopt;
    if (!c.fixed(cert.position.validator_set_root)) return std::nullopt;
    if (!c.u32(cert.threshold)) return std::nullopt;

    std::uint32_t count = 0;
    if (!c.u32(count)) return std::nullopt;

    // A count is not a capacity. Each record is at least its fixed part, so a
    // count that cannot fit in what remains is refused before a single byte is
    // reserved for it. (Go caps against the whole buffer rather than the
    // remainder; the difference is which clause refuses, never whether. Any
    // count this admits and Go's does not still runs out of bytes at the first
    // record and refuses there.)
    if (std::size_t(count) > c.left() / kCertVoteFixedLen) return std::nullopt;

    cert.votes.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        Vote v;
        std::uint8_t accept = 0;
        std::uint32_t sig_len = 0;
        if (!c.fixed(v.node)) return std::nullopt;
        if (!c.u8(accept)) return std::nullopt;
        if (accept > 1) return std::nullopt;  // one byte, two meanings, nothing else
        v.accept = accept == 1;
        if (!c.u32(sig_len)) return std::nullopt;
        if (!c.take(sig_len, v.signature)) return std::nullopt;
        cert.votes.push_back(std::move(v));
    }
    // A trailing byte is a refusal: an encoder that appends is not speaking this
    // protocol, and accepting the remainder would give one certificate many
    // byte strings.
    if (!c.done()) return std::nullopt;

    why = Refusal::None;
    return cert;
}

std::vector<std::uint8_t> Cert::message() const {
    return canonical_vote_message(position, true);
}

Refusal Cert::verify(const Keys& keys) const {
    if (version != kQuorumCertVersion) return Refusal::Version;
    if (role != kQCFinality) return Refusal::Role;
    if (tier != Tier::Nova && tier != Tier::Quasar) return Refusal::Tier;
    if (threshold == 0) return Refusal::ThresholdZero;
    if (votes.empty()) return Refusal::NoVotes;

    const std::vector<std::uint8_t> msg = message();
    std::uint32_t count = 0;
    bool have_prev = false;
    Node prev{};
    for (const Vote& v : votes) {
        if (have_prev && !(prev < v.node)) return Refusal::Order;
        prev = v.node;
        have_prev = true;

        if (!v.accept) return Refusal::NotAccept;
        if (!keys.verify(v.node, msg.data(), msg.size(), v.signature.data(), v.signature.size()))
            return Refusal::Signature;
        ++count;
    }
    if (count < threshold) return Refusal::BelowThreshold;
    return Refusal::None;
}

// ── the validator set ────────────────────────────────────────────────────────

struct Registry::Key {
    blst_p1_affine pk{};
};

bool Registry::insert(const Node& node, const PubKey& compressed) {
    auto key = std::make_shared<Key>();
    if (blst_p1_uncompress(&key->pk, compressed.data()) != BLST_SUCCESS) return false;
    // Subgroup AND identity, once. blst_p1_affine_is_inf is the identity test;
    // an identity public key verifies a signature over any message, so it is
    // refused at the boundary rather than carried to every later verification.
    if (blst_p1_affine_is_inf(&key->pk)) return false;
    if (!blst_p1_affine_in_g1(&key->pk)) return false;

    // ONE KEY, ONE NODE — Go's ErrDuplicateKey. The hazard this closes is the
    // reason the admission door was written: a holder seated under two node ids
    // is two votes on one signature, and Cert::verify is right to count them,
    // because it counts what the set told it. The set declines to say it.
    if (seated_.contains(compressed)) return false;
    // ONE NODE, ONE KEY — Go's ErrDuplicateNode, and the axis an overwriting
    // seat used to hide: re-seating a node under a second key silently retired
    // the first, so a certificate signed under the key this set was built around
    // stopped verifying against it. Neither axis implies the other.
    if (keys_.contains(node)) return false;

    // Both indices move together or neither does; nothing above has written.
    keys_.emplace(node, std::move(key));
    seated_.insert(compressed);
    return true;
}

bool Registry::verify(const Node& node,
                      const std::uint8_t* message, std::size_t message_len,
                      const std::uint8_t* signature, std::size_t signature_len) const {
    const auto it = keys_.find(node);
    if (it == keys_.end()) return false;  // an unknown voter is a refusal, not a skip
    if (signature_len != 96) return false;

    blst_p2_affine sig{};
    if (blst_p2_uncompress(&sig, signature) != BLST_SUCCESS) return false;
    // The signature's group check, once. The key's was paid at insert.
    if (!blst_p2_affine_in_g2(&sig)) return false;

    // ONE pairing, in bls.cpp. A validator set does not get its own opinion
    // about how a signature is checked.
    return bls::pair(it->second->pk, sig, message, message_len);
}

}  // namespace lux::consensus
