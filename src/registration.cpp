// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// registration.cpp — the admission door. See registration.hpp for why the order
// of the clauses is the rule and not decoration.

#include "lux/consensus/registration.hpp"

#include <blst.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace lux::consensus {

const char* admission_name(Admission::Why why) noexcept {
    switch (why) {
        case Admission::Why::Ok:             return "ok";
        case Admission::Why::NoKey:          return "no_key";
        case Admission::Why::ZeroWeight:     return "zero_weight";
        case Admission::Why::Possession:     return "possession";
        case Admission::Why::DuplicateKey:   return "duplicate_key";
        case Admission::Why::DuplicateNode:  return "duplicate_node";
        case Admission::Why::WeightOverflow: return "weight_overflow";
    }
    return "unknown";
}

std::vector<Validator> CanonicalSet::weights() const {
    std::vector<Validator> out;
    out.reserve(validators.size());
    for (const CanonicalValidator& v : validators) out.push_back(Validator{v.key, v.weight});
    return out;
}

bool CanonicalSet::install(Registry& keys) const {
    // No carryover: a registry that already holds a set is not this set.
    if (keys.size() != 0) return false;

    // Seated whole or not at all, exactly as the set was admitted whole or not
    // at all — and for the same reason. A midway refusal that left a PREFIX
    // behind would leave a registry resolving some of this set's nodes and none
    // of the rest, which is a validator set nobody chose: the floors are taken
    // of a total this half-registry does not have. So it is built beside the
    // caller's and moved in only once every seat is taken.
    Registry seated;
    for (const CanonicalValidator& v : validators)
        if (!seated.insert(v.node, v.key)) return false;
    keys = std::move(seated);
    return true;
}

Admission admit(std::vector<Registration> rs, CanonicalSet& set) {
    // A refused call returns no partial set: the caller must not be able to read
    // a validator list out of a verdict that said no.
    set = CanonicalSet{};

    // Deterministic order in, deterministic verdict out. WHICH registration a set
    // is refused on must not depend on the order a caller happened to build the
    // vector in, or two nodes given the same set disagree about it. Stable, so
    // that two registrations sharing a node id — the DuplicateNode case, the one
    // pair this sort cannot separate — keep their relative order.
    std::stable_sort(rs.begin(), rs.end(), [](const Registration& a, const Registration& b) {
        return a.node < b.node;
    });

    std::map<PubKey, Node> by_key;   // the key → the node that holds it
    std::set<Node>         by_node;  // the nodes already seated

    CanonicalSet out;
    out.validators.reserve(rs.size());

    for (const Registration& r : rs) {
        // A validator with no key cannot sign, so it cannot be admitted through
        // the proof path at all — a distinct answer from a key that is present
        // and wrong, which is a possession refusal below.
        if (r.key.empty()) return Admission{.why = Admission::Why::NoKey, .node = r.node};

        // A keyed validator with no stake is a phantom signer: it raises the
        // count of distinct signers without raising the weight, which is the
        // disagreement between "how many signed" and "how much signed" that the
        // two tier floors exist to keep in step.
        if (r.weight == 0) return Admission{.why = Admission::Why::ZeroWeight, .node = r.node};

        // ENCODING. The widths first, because pop_verify reads fixed-width
        // buffers: a short key is a key that was never a point, and reading 48
        // bytes out of 47 is the bug the length check exists to prevent. The
        // class matches the leg Go's pop.Verify refuses on.
        if (r.key.size() != kKeyLen)
            return Admission{.why        = Admission::Why::Possession,
                             .node       = r.node,
                             .possession = bls::Pop::Key};
        if (r.proof.size() != kProofLen)
            return Admission{.why        = Admission::Why::Possession,
                             .node       = r.node,
                             .possession = bls::Pop::Proof};

        // ENCODING, then POSSESSION — both inside pop_verify, in that order, and
        // byte-for-byte the Go oracle: a non-canonical, off-subgroup or identity
        // point is Key/Proof, and a proof that decodes but does not bind this
        // node to this key is Possession.
        if (const bls::Pop p = bls::pop_verify(r.node.data(), r.key.data(), r.proof.data());
            p != bls::Pop::Ok)
            return Admission{.why = Admission::Why::Possession, .node = r.node, .possession = p};

        // The canonical spelling of the key, taken from the POINT and never from
        // the caller's bytes. One point, one encoding: a registrant does not get
        // to choose which 48 bytes the set carries, because the set is keyed on
        // them and a second spelling of one key would be a second signer. That
        // the round trip LANDS on the caller's bytes is pop_verify's Key clause,
        // where Go keeps it too, so the door reads the point rather than
        // re-deciding what a canonical key is.
        blst_p1_affine point;
        if (blst_p1_uncompress(&point, r.key.data()) != BLST_SUCCESS)
            return Admission{.why        = Admission::Why::Possession,
                             .node       = r.node,
                             .possession = bls::Pop::Key};  // unreachable: pop_verify decoded it
        PubKey canonical{};
        blst_p1_affine_compress(canonical.data(), &point);

        // UNIQUENESS OF KEY. Possession does NOT catch this: the holder of a key
        // can mint a genuine node-bound proof for any identity it likes, so every
        // registration in a many-nodes-one-key set is individually sound. Only the
        // set-level rule refuses it, and counting distinct voters has to count
        // distinct signers.
        if (const auto it = by_key.find(canonical); it != by_key.end())
            return Admission{.why    = Admission::Why::DuplicateKey,
                             .node   = r.node,
                             .holder = it->second};
        by_key.emplace(canonical, r.node);

        // UNIQUENESS OF NODE, the other axis. One node id under two keys, each
        // with a genuine proof: possession does not catch that either, and one
        // operator in two canonical seats is two signer indices and two shares of
        // the weight under one identity.
        if (!by_node.insert(r.node).second)
            return Admission{.why = Admission::Why::DuplicateNode, .node = r.node};

        // WEIGHT, last, and checked before it is added: the total is what both
        // stake floors are taken of, so a total that wrapped is a floor that lies.
        if (out.total_weight > std::numeric_limits<std::uint64_t>::max() - r.weight)
            return Admission{.why = Admission::Why::WeightOverflow, .node = r.node};
        out.total_weight += r.weight;

        out.validators.push_back(CanonicalValidator{r.node, canonical, r.weight});
    }

    // Canonical order: ascending by the compressed key. Keys are distinct by the
    // rule just enforced, so the order is total and needs no tie-break.
    std::sort(out.validators.begin(), out.validators.end(),
              [](const CanonicalValidator& a, const CanonicalValidator& b) { return a.key < b.key; });

    set = std::move(out);
    return Admission{};
}

}  // namespace lux::consensus
