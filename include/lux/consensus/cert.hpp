// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// cert.hpp — the PORTABLE finality certificate: Go engine/chain.QuorumCert and
// Rust lux_consensus::finality::Cert, in C++, byte for byte.
//
// WHY THIS EXISTS. C++ already had a certificate — QuorumCert in
// quorum_cert_engine.hpp — and it is a DIFFERENT OBJECT from the one the other
// two implementations gossip:
//
//              Go / Rust                        C++ QuorumCertEngine
//   carries    per-voter signatures             ONE aggregate signature
//   keyed by   node id (20 bytes)               public key (48 bytes)
//   predicate  one pairing PER VOTE             one aggregate pairing, O(1)
//   wire       encode/decode, 280-byte header   none — it never crossed a wire
//
// Neither side can read the other's bytes, so a C++ node could not verify a
// certificate a Go node produced, and the C++ figure for "verify a certificate"
// was timing a predicate the other two do not run. Go is the oracle; this is
// the oracle's object.
//
// The aggregate engine keeps its job. It is the LOCAL gate: a node that
// collected the votes itself already holds the keys and can afford to fold them
// once. This type is the INTEROP object: what arrives from another node, in the
// form the other node sent it. Two names because they are two things.
//
// The layout is engine/chain/cert_codec.go, big-endian throughout:
//
//   version:2  type:1  tier:1
//   chain_id:32  height:8  round:4
//   block_id:32  parent_id:32                 (transport identity — NOT signed)
//   canonical_id:32  parent_canonical_id:32
//   execution_state_root:32  payload_root:32
//   validator_set_root:32                     (canonical identity — signed)
//   threshold:4  vote_count:4
//   then vote_count records of: node:20  accept:1  sig_len:4  sig:sig_len
//
// 280 bytes of header. Decoding is fail-closed on every short read, refuses a
// trailing byte (one certificate, one byte string), and caps the attacker-named
// vote count against what is left in the buffer BEFORE allocating for it.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // VotePosition, Tier, Id, PubKey, Signature

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

namespace lux::consensus {

// A validator's transport identity — Go ids.NodeID, Rust Node. Twenty bytes,
// and NOT the public key: the certificate names who voted, and the verifier
// resolves that name to a key it already trusts.
inline constexpr std::size_t kNodeLen = 20;
using Node = std::array<std::uint8_t, kNodeLen>;

// The fixed header, and the fixed part of one vote record. Named so the
// decode-DoS cap reads as arithmetic rather than as a magic number.
inline constexpr std::size_t kCertHeaderLen = 2 + 1 + 1 + 32 + 8 + 4 + 32 * 7 + 4 + 4;  // 280
inline constexpr std::size_t kCertVoteFixedLen = kNodeLen + 1 + 4;                      // 25

// Why a certificate is not finality. Every value is a refusal; there is no
// value that means "probably fine". Mirrors Rust's Refusal and Go's Err QC*.
enum class Refusal {
    None,
    Version,          // not the version this network certifies under
    Role,             // the role byte is not a finality attestation
    Tier,             // a certificate attests Nova or Quasar, nothing else
    ThresholdZero,    // a quorum of nobody
    NoVotes,          // attests nothing
    Order,            // node ids not strictly increasing — a double count or a re-ordering
    NotAccept,        // a finality certificate carries ACCEPT votes only
    Signature,        // a signature did not verify against its resolved key
    BelowThreshold,   // fewer valid distinct accept votes than the floor
    Wire,             // short read, trailing byte, or an impossible vote count
};

[[nodiscard]] const char* refusal_name(Refusal r) noexcept;

// One voter's signed record, as it travels.
struct Vote {
    Node                      node{};
    bool                      accept = false;
    std::vector<std::uint8_t> signature;
};

// Resolves a node id to the key that node votes with, and answers whether a
// signature holds. A node this does not know is a refusal, never a skip: a
// majority of an unknown set is not a majority.
class Keys {
public:
    virtual ~Keys() = default;
    [[nodiscard]] virtual bool verify(const Node& node,
                                      const std::uint8_t* message, std::size_t message_len,
                                      const std::uint8_t* signature, std::size_t signature_len) const = 0;
};

// The gossiped witness.
struct Cert {
    std::uint16_t     version = kQuorumCertVersion;
    std::uint8_t      role    = kQCFinality;   // Go calls this Type
    Tier              tier    = Tier::Quasar;
    VotePosition      position{};
    std::uint32_t     threshold = 0;
    std::vector<Vote> votes;

    // The exact bytes this certificate is gossiped as.
    [[nodiscard]] std::vector<std::uint8_t> encode() const;

    // Read one off the wire, or say why not.
    [[nodiscard]] static std::optional<Cert> decode(const std::uint8_t* data, std::size_t len,
                                                    Refusal& why);

    // The one message every signature in this certificate is checked against,
    // derived from the certificate's OWN position — so a vote that signed a
    // different position fails, which is the point.
    [[nodiscard]] std::vector<std::uint8_t> message() const;

    // The structural and signature predicate, tier-agnostic. Byte-for-byte the
    // clause order of Go's QuorumCert.Verify and Rust's Cert::verify: version,
    // role, tier, threshold, non-empty, then per vote — strictly increasing
    // node, accept, signature — then the count against the floor. There is no
    // path that returns None without every signature having verified against a
    // resolved key.
    [[nodiscard]] Refusal verify(const Keys& keys) const;
};

// The admitted set — registration.hpp. Seating a Registry is its business, and
// only its business; the name is here so it can be said so below.
struct CanonicalSet;

// A validator set that resolves node ids to DECOMPRESSED public keys.
//
// The key is uncompressed and subgroup-checked ONCE, here, at registration —
// so a verification pays for the signature it is checking and not for a key it
// already trusts. This is the work split Go's verifier makes, and it is the
// split that makes a per-verify figure comparable across the three languages.
//
// IT IS A BIJECTION, and that is what makes counting votes mean anything. A
// certificate is verified by counting one vote per DISTINCT node id against the
// floor; if two node ids resolved to one key, one holder's single signature would clear
// a floor written to require two signers, and no clause of the verifier could
// tell — it was handed a set that says two nodes signed. So the set itself
// refuses to be that: one node resolves to one key, one key answers for one
// node, and neither direction implies the other.
//
// THE ONE WAY IN IS CanonicalSet::install. Seating is private and the admitted
// set is its only friend, so every live Registry came through the admission door
// — where possession was demanded — rather than out of a caller's own idea of
// who the validators are.
class Registry : public Keys {
public:
    [[nodiscard]] bool verify(const Node& node,
                              const std::uint8_t* message, std::size_t message_len,
                              const std::uint8_t* signature, std::size_t signature_len) const override;

    [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }

private:
    // Seat one validator under its compressed public key. Refuses a point that
    // does not uncompress, one outside the subgroup, and the identity — an
    // identity public key verifies a signature over any message. Then the two
    // uniqueness axes, in Go's order (ErrDuplicateKey, then ErrDuplicateNode):
    // a key already seated under another node, and a node already seated. A
    // refusal seats nothing.
    bool insert(const Node& node, const PubKey& compressed);

    // install() is the seating route, so it is the one thing that may call it.
    friend struct CanonicalSet;

    struct Key;                                  // a decompressed G1 affine
    std::map<Node, std::shared_ptr<const Key>> keys_;
    std::set<PubKey>                           seated_;  // the keys already spoken for
};

}  // namespace lux::consensus
