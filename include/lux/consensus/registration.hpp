// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// registration.hpp — who is admitted to the validator set, and on what evidence.
// The C++ side of Go validator/registration.go, clause for clause.
//
// A certificate is only as sound as the SET it is checked against. cert.hpp
// verifies a witness against a Registry, and quorum_cert_engine.hpp counts
// distinct voters against a stake floor — both are exact, and both are exactly
// as meaningful as the set someone handed them. Until now C++ had no door: a
// caller built a Registry by calling insert() with whatever pairs it liked, so
// one key holder could be seated under many node ids and a floor written to
// require many DISTINCT signers was cleared by one. The proof primitive to close
// that has been here since bls::pop_verify; this is the place that demands it.
//
// THE ORDER IS THE RULE, and it is not decoration:
//
//   ENCODING     the key is a canonical compressed BLS12-381 G1 point, and the
//                proof a canonical compressed G2 one. A pairing on bytes that
//                are not a point is undefined, so nothing is admitted — and no
//                pairing is computed — on a point that was never a point.
//   POSSESSION   a node-bound proof (bls::pop_verify, the frozen corpus in
//                vectors/pop.json) binds THIS key to THIS node. The IETF
//                pubkey-only proof is not enough: it is a statement about a key,
//                so it travels with the key, and anyone can re-present the pair
//                under a second identity.
//   UNIQUENESS   on BOTH axes, and neither implies the other. One key, one node:
//                counting distinct voters has to count distinct signers. One
//                node, one key: a node seated twice is two signer indices and
//                two shares of the weight under one identity, and possession
//                does not catch it, because both proofs are genuine.
//   WEIGHT       counted last. Weight counted before uniqueness is weight
//                counted twice.
//
// THE SET IS ADMITTED WHOLE OR NOT AT ALL. One unproven or duplicated
// registration fails the call rather than being dropped from an otherwise-good
// set: a set that silently loses a signer is a set whose total weight no longer
// describes it, and the stake floors are computed from that total.
//
// A refusal is a function of the SET, never of the order a caller happened to
// build a vector in — the registrations are walked in node-id order, so two
// nodes given the same set refuse the same registration for the same reason.

#pragma once

#include "lux/consensus/bls.hpp"                 // pop_verify, and the class it refuses under
#include "lux/consensus/cert.hpp"                // Node — the 20-byte identity — and Registry
#include "lux/consensus/quorum_cert_engine.hpp"  // PubKey, Signature, Validator

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

namespace lux::consensus {

// THE VALIDATOR IDENTITY IS THE 20-BYTE NODE ID — lux::consensus::Node, declared
// once in cert.hpp as the identity a certificate's votes carry, and it is the
// same 20 bytes the proof of possession binds. Two spellings of that width exist
// in this tree (cert.hpp's kNodeLen for the wire, bls.hpp's for the proof
// preimage); they are pinned to each other here so a change to one that is not a
// change to the other cannot compile. A proof that bound a different identity
// would bind something the set does not use to decide who signed.
static_assert(bls::kNodeLen == kNodeLen,
              "the identity a proof binds and the identity a certificate names are one identity");

// The widths, derived from the types that already carry them rather than written
// again: a compressed G1 public key and a compressed G2 point (a proof is a G2
// point, the same width as a vote signature and never the same message).
inline constexpr std::size_t kKeyLen   = std::tuple_size_v<PubKey>;     // 48
inline constexpr std::size_t kProofLen = std::tuple_size_v<Signature>;  // 96

// One validator asking to be counted: the identity it claims, the key it will
// sign under, the proof binding the two, and the weight staked behind it.
//
// key and proof are byte strings rather than fixed arrays because a WRONG WIDTH
// is a thing a registrant can present and the door has to have an answer for it
// — the same reason Go carries them as slices. An absent key and a 47-byte key
// are different refusals, and neither is representable in a std::array.
struct Registration {
    Node                      node{};
    std::vector<std::uint8_t> key;    // compressed G1, kKeyLen bytes
    std::vector<std::uint8_t> proof;  // compressed G2, kProofLen bytes, over node ‖ key
    std::uint64_t             weight = 0;
};

// An admitted validator: exactly ONE node id, and the canonical spelling of its
// key. Go's CanonicalValidator, with the merge retired — upstream folded two node
// ids that shared a key into one entry carrying both, and that fold is the only
// thing that ever made many-nodes-one-key representable.
struct CanonicalValidator {
    Node          node{};
    PubKey        key{};  // re-serialized from the decoded point, not the caller's bytes
    std::uint64_t weight = 0;
};

// The admitted set. Go's CanonicalValidatorSet.
//
// ORDERED ASCENDING BY THE COMPRESSED KEY, which is what makes it canonical: the
// order decides signature bit indices, so every node that admits the same
// registrations holds the same set in the same order. Compressed — never the
// uncompressed form, which is 96 bytes under one crypto build and 48 under
// another and orders the same set two ways.
struct CanonicalSet {
    std::vector<CanonicalValidator> validators;
    std::uint64_t                   total_weight = 0;

    // The weighted set the finality gate is constructed over. The admitted set is
    // the ONE producer of a QuorumCertEngine's validators, so a gate can never be
    // built over keys that were never proven.
    [[nodiscard]] std::vector<Validator> weights() const;

    // Seat every admitted validator in a Registry, so a gossiped certificate is
    // checked against the set that was admitted and not one assembled by hand.
    //
    // `keys` MUST BE EMPTY, and false is the refusal when it is not. A set
    // rotation seats a fresh Registry exactly as it constructs a fresh engine:
    // seating over a live one would leave the PREVIOUS set's nodes resolvable, so
    // a retired validator's vote would still find a key and "an unknown voter is
    // a refusal" would quietly become "a retired voter is counted". That is the
    // one way this set reaches the certificate verifier, so it is the one place
    // the carryover has to be impossible rather than merely discouraged.
    //
    // A key admission already proved decodes cannot be refused by insert(), so
    // beyond the emptiness clause false is the invariant failing loud.
    [[nodiscard]] bool install(Registry& keys) const;
};

// The answer the door gives. Ok, or the clause that refused and the registration
// it fell on.
struct Admission {
    enum class Why : std::uint8_t {
        Ok,
        NoKey,           // carries no public key at all: it cannot sign, so it cannot be seated
        ZeroWeight,      // a phantom signer — counts toward the signer floor, not the stake floor
        Possession,      // the proof does not bind this node to this key (see `possession`)
        DuplicateKey,    // this key is already seated under another node (see `holder`)
        DuplicateNode,   // this node is already seated under another key
        WeightOverflow,  // the summed weight does not fit the total the floors are taken of
    };

    Why      why = Why::Ok;
    Node     node{};                     // the registration the refusal fell on
    Node     holder{};                   // DuplicateKey: the node already holding the key
    bls::Pop possession = bls::Pop::Ok;  // Possession: which clause of the proof refused

    [[nodiscard]] explicit operator bool() const noexcept { return why == Why::Ok; }
};

[[nodiscard]] const char* admission_name(Admission::Why why) noexcept;

// THE DOOR. Admits `rs` and writes the canonical set, or returns the clause that
// refused it and leaves `set` empty — a refused call never returns a partial set.
//
// `rs` is taken BY VALUE: the walk order is this function's business (it sorts by
// node id to make the verdict a function of the set), and a caller's vector is
// not something to reorder behind its back.
[[nodiscard]] Admission admit(std::vector<Registration> rs, CanonicalSet& set);

}  // namespace lux::consensus
