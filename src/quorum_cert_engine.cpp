// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// quorum_cert_engine.cpp — finality gate implementation. The RULE lives here;
// the CRYPTO is lux::consensus::bls (the Lux consensus vote domain over blst).

#include "lux/consensus/quorum_cert_engine.hpp"

#include "lux/consensus/bls.hpp"

#include <cstdint>
#include <stdexcept>

namespace lux::consensus {

namespace {

// Big-endian append helpers — fixed-width, so the message is length-free and a
// field can never be confused with its neighbour (Go's layout).
void put_be16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(std::uint8_t(v >> 8));
    b.push_back(std::uint8_t(v));
}
void put_be32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
}
void put_be64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
}
void put_id(std::vector<std::uint8_t>& b, const Id& id) {
    b.insert(b.end(), id.begin(), id.end());
}

// Domain tag, NUL-terminated as a hard role separator. v2 == the
// canonical-commitment layout: the signed identity is the inner execution
// commitment, never the outer envelope id.
constexpr char        kDomainTag[]  = "LUX/chain/vote/v2\x00";
constexpr std::size_t kDomainTagLen = sizeof(kDomainTag) - 1;  // keeps the NUL, drops C's terminator

// Verify one validator's BLS signature over `msg` in the consensus vote domain.
// bls::verify returns 0 on success, 1 on mismatch, <0 on decode error.
[[nodiscard]] bool bls_verify(const PubKey& voter,
                              const std::vector<std::uint8_t>& msg,
                              const Signature& sig) noexcept {
    return bls::verify(voter.data(), msg.data(), msg.size(), sig.data()) == 0;
}

}  // namespace

Id canonical_id_of(const VotePosition& pos) noexcept {
    return pos.canonical_id == kEmptyId ? pos.block_id : pos.canonical_id;
}

Id parent_canonical_id_of(const VotePosition& pos) noexcept {
    return pos.parent_canonical_id == kEmptyId ? pos.parent_id : pos.parent_canonical_id;
}

std::vector<std::uint8_t> canonical_vote_message(const VotePosition& pos, bool accept) {
    std::vector<std::uint8_t> buf;
    buf.reserve(kDomainTagLen + 2 + 1 + 32 + 8 + 4 + 32 * 5 + 1);
    buf.insert(buf.end(), kDomainTag, kDomainTag + kDomainTagLen);  // domain + NUL
    put_be16(buf, kQuorumCertVersion);
    buf.push_back(kQCFinality);
    put_id(buf, pos.chain_id);
    put_be64(buf, pos.height);
    put_be32(buf, pos.round);
    // Canonical execution identity — the signed primary object. Outer ids omitted.
    put_id(buf, canonical_id_of(pos));
    put_id(buf, parent_canonical_id_of(pos));
    put_id(buf, pos.execution_state_root);
    put_id(buf, pos.payload_root);
    put_id(buf, pos.validator_set_root);
    buf.push_back(accept ? 0x01 : 0x00);
    return buf;
}

QuorumCertEngine::QuorumCertEngine(std::vector<Validator> validators) : total_stake_(0) {
    if (validators.empty())
        throw std::invalid_argument("consensus: empty validator set");

    for (const auto& v : validators) {
        if (v.stake == 0)
            throw std::invalid_argument("consensus: in-set validator has zero stake");
        // A VALIDATOR IS A SIGNER, enforced rather than assumed. A PubKey is a
        // 48-byte array, so it is always PRESENT and presence proves nothing: 48
        // zero bytes are a well-formed value and not a point of G1. Such a seat
        // holds stake in every denominator and can never produce a signature this
        // engine accepts, which is exactly the spectator this implementation was
        // said to have no slot for — stranding the export rung as surely as a
        // keyless member does in Go and Rust, and silently, because nothing else
        // here ever decodes the key until a vote arrives that never comes.
        //
        // So the key is decoded HERE, once, through the same bls::key_validate
        // the proof-of-possession path decodes it with: canonical compressed G1,
        // in the prime-order subgroup, not the identity. A dead key is a
        // construction error and not a runtime surprise.
        if (!bls::key_validate(v.pubkey.data()))
            throw std::invalid_argument("consensus: in-set validator public key is not a G1 point");
        if (!validators_.emplace(v.pubkey, v.stake).second)
            throw std::invalid_argument("consensus: duplicate validator pubkey");
        // Checked add: a wrapped total_stake_ would corrupt the stake floors and is a
        // safety bug, not a config error. Fail closed at construction instead.
        if (total_stake_ > UINT64_MAX - v.stake)
            throw std::invalid_argument("consensus: total stake overflows uint64");
        total_stake_ += v.stake;
    }
}

std::uint32_t QuorumCertEngine::signer_floor(Tier tier) const noexcept {
    // Both derived from the live set, neither configured. The export floor is the
    // supermajority in seats — the same one the stake floor below asks for in
    // stake — so a certificate must carry two thirds of the parties AND two thirds
    // of the weight. Reading only stake makes "supermajority" mean one signature
    // wherever the weight is concentrated in one validator.
    return tier == Tier::Quasar ? two_thirds_count(validator_count())
                                : nova_signer_floor(validator_count());
}

std::uint64_t QuorumCertEngine::stake_floor(Tier tier) const noexcept {
    return tier == Tier::Quasar ? two_thirds_stake_floor(total_stake_)
                                : half_stake_floor(total_stake_);
}

std::uint32_t QuorumCertEngine::committee_floor(Tier tier) noexcept {
    // The third floor, and the only one read against the SET rather than against
    // the votes. Byzantine tolerance is f = (n-1)/3, which is 0 for n of one, two
    // and three: below four signers a two-thirds supermajority tolerates no fault
    // at all, so a unanimous certificate over such a set is forged by any single
    // compromised key among its signers.
    //
    // Neither floor above catches it, because both are read over n and both
    // therefore shrink with it — two_thirds_count(1) is 1, so one signature is a
    // supermajority of one over a stake floor the same signature clears outright.
    //
    // Nova floors at one: it authorizes only local execution the chain can still
    // reorg away, is crash-fault-safe rather than Byzantine-safe by construction,
    // and a floor of four there would stop a small chain making any progress in
    // exchange for a guarantee the rung never offered.
    return tier == Tier::Quasar ? kMinBFTCommittee : 1;
}

std::uint64_t QuorumCertEngine::stake_of(const PubKey& voter) const {
    const auto it = validators_.find(voter);
    return it == validators_.end() ? 0 : it->second;
}

bool QuorumCertEngine::drop(const BlockId& block_id) {
    const std::lock_guard<std::mutex> lock(mu_);
    return pending_.erase(block_id) != 0;
}

bool QuorumCertEngine::submit(const VotePosition& pos) {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto [it, inserted] = pending_.try_emplace(pos.block_id);
    if (!inserted) return false;  // already pending — idempotent guard
    Pending& p = it->second;
    p.pos = pos;
    p.message = canonical_vote_message(pos);
    return true;
}

std::optional<VotePosition> QuorumCertEngine::position(const BlockId& block_id) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pending_.find(block_id);
    if (it == pending_.end()) return std::nullopt;
    return it->second.pos;
}

VoteResult QuorumCertEngine::record_vote(const BlockId& block_id,
                                         const PubKey& voter,
                                         const Signature& sig) {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto pit = pending_.find(block_id);
    if (pit == pending_.end()) return VoteResult::RejectedNoSuchBlock;
    Pending& p = pit->second;

    // Out-of-set keys carry no stake and can never be a quorum member.
    const std::uint64_t stake = stake_of(voter);
    if (stake == 0) return VoteResult::RejectedUnknownValidator;

    // Dedup by validator key: a replay of an already-recorded voter is cheaply
    // rejected and can never double-count.
    if (p.votes.find(voter) != p.votes.end()) return VoteResult::Duplicate;

    if (p.verified) {
        // The tally is already verified. An extra vote joins only after its own
        // individual pairing passes, so the "every counted voter is verified"
        // invariant is preserved.
        if (!bls_verify(voter, p.message, sig)) return VoteResult::RejectedBadSignature;
        p.votes.emplace(voter, sig);
        p.voted_stake += stake;
        return VoteResult::Recorded;
    }

    // Join as a CANDIDATE with no per-vote pairing. BLS over the same message
    // aggregates, so verification is O(1) (one aggregate pairing), not O(m)
    // individual ones — and it runs where the answer is needed: at the gate.
    p.votes.emplace(voter, sig);
    p.voted_stake += stake;
    return VoteResult::Recorded;
}

bool QuorumCertEngine::batch_verify(const Pending& p) const {
    std::vector<std::uint8_t> pks, sigs;
    pks.reserve(p.votes.size() * 48);
    sigs.reserve(p.votes.size() * 96);
    for (const auto& [pk, sig] : p.votes) {
        pks.insert(pks.end(), pk.begin(), pk.end());
        sigs.insert(sigs.end(), sig.begin(), sig.end());
    }
    Signature agg{};
    if (bls::aggregate_sigs(sigs.data(), p.votes.size(), agg.data()) != 0)
        return false;
    // Same canonical message for every voter ⇒ fast_aggregate_verify is one pairing.
    return bls::fast_aggregate_verify(pks.data(), p.votes.size(),
                                      p.message.data(), p.message.size(), agg.data()) == 0;
}

void QuorumCertEngine::verify_tally(Pending& p) const {
    if (p.verified || p.votes.empty()) return;
    if (batch_verify(p)) {
        p.verified = true;  // ONE pairing certifies the whole tally
        return;
    }
    // The aggregate failed ⇒ ≥1 candidate sig is bad. Pay the O(m) individual
    // verify ONLY on this attack path; drop forged sigs and refund their stake.
    for (auto it = p.votes.begin(); it != p.votes.end();) {
        if (!bls_verify(it->first, p.message, it->second)) {
            p.voted_stake -= stake_of(it->first);
            it = p.votes.erase(it);
        } else {
            ++it;
        }
    }
    // Every survivor is now individually verified, so the invariant holds whether or
    // not the survivors still clear a floor. Marking it settles the tally: this block
    // has seen forgery, so its later votes pay an individual pairing each rather than
    // re-running an aggregate that a griefer can keep breaking.
    p.verified = true;
}

bool QuorumCertEngine::clears_floors(const Pending& p, Tier tier) const noexcept {
    // FAIL-CLOSED: no stake model ⇒ no majority of an unknown set can be asserted.
    if (total_stake_ == 0) return false;
    if (validator_count() < committee_floor(tier)) return false;
    if (p.votes.size() < signer_floor(tier)) return false;
    return p.voted_stake > stake_floor(tier);  // STRICT
}

bool QuorumCertEngine::meets_quorum(Pending& p, Tier tier) const {
    // Cheap floors first: below them there is nothing to verify and no pairing is
    // spent, so an unverified tally is never a way to make the gate do work.
    if (!clears_floors(p, tier)) return false;
    // VERIFIED: a BLS check covering every counted voter must have passed. This is
    // where it runs, once, and where a forged candidate is evicted.
    verify_tally(p);
    // Re-check: eviction can drop a tally back below the floors it just cleared.
    return p.verified && clears_floors(p, tier);
}

bool QuorumCertEngine::is_final(const BlockId& block_id, Tier tier) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pending_.find(block_id);
    return it != pending_.end() && meets_quorum(it->second, tier);
}

std::size_t QuorumCertEngine::distinct_voters(const BlockId& block_id) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pending_.find(block_id);
    return it == pending_.end() ? 0 : it->second.votes.size();
}

std::uint64_t QuorumCertEngine::voted_stake(const BlockId& block_id) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pending_.find(block_id);
    return it == pending_.end() ? 0 : it->second.voted_stake;
}

std::optional<QuorumCert> QuorumCertEngine::assemble_cert(const BlockId& block_id,
                                                          Tier tier) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto pit = pending_.find(block_id);
    if (pit == pending_.end() || !meets_quorum(pit->second, tier)) return std::nullopt;
    const Pending& p = pit->second;

    // votes is a std::map keyed by pubkey ⇒ iteration is already strictly-ascending
    // and distinct — exactly the canonical "strictly increasing voter" order.
    QuorumCert cert;
    cert.version     = kQuorumCertVersion;
    cert.type        = kQCFinality;
    cert.tier        = tier;
    cert.position    = p.pos;
    cert.threshold   = signer_floor(tier);
    cert.voted_stake = p.voted_stake;
    cert.total_stake = total_stake_;

    std::vector<std::uint8_t> sigs_flat;
    sigs_flat.reserve(p.votes.size() * 96);
    cert.voters.reserve(p.votes.size());
    for (const auto& [pk, sig] : p.votes) {
        cert.voters.push_back(pk);
        sigs_flat.insert(sigs_flat.end(), sig.begin(), sig.end());
    }

    // Aggregate the per-voter G2 signatures into one. All voters signed the SAME
    // canonical message, so the aggregate re-verifies via fast_aggregate_verify.
    if (bls::aggregate_sigs(sigs_flat.data(), cert.voters.size(),
                            cert.aggregate_sig.data()) != 0) {
        return std::nullopt;  // structurally impossible for verified inputs; fail closed
    }
    return cert;
}

bool QuorumCertEngine::verify_cert(const QuorumCert& cert) const {
    // (1) version + role.
    if (cert.version != kQuorumCertVersion || cert.type != kQCFinality) return false;
    // (2) tier is one of the two attestable rungs, and the cert's self-declared
    //     threshold matches the floor THIS set derives for that tier. The floor is
    //     recomputed below regardless — a cert can never talk its way past it.
    if (cert.tier != Tier::Nova && cert.tier != Tier::Quasar) return false;
    const std::uint32_t floor_count = signer_floor(cert.tier);
    if (cert.threshold == 0 || cert.threshold != floor_count) return false;
    // (3) fail-closed on no stake model, and on a set too small for the tier's
    //     fault model to mean anything. The second is the floor on the SET; see
    //     committee_floor. Both entry points read it, so a certificate cannot
    //     enter through the one that forgot.
    if (total_stake_ == 0) return false;
    if (validator_count() < committee_floor(cert.tier)) return false;
    if (cert.voters.empty()) return false;

    // (4) voters strictly increasing (distinct, canonical order) AND all in-set;
    //     accumulate stake from the AUTHORITATIVE set, never trusting cert fields.
    std::uint64_t voted = 0;
    for (std::size_t i = 0; i < cert.voters.size(); ++i) {
        if (i > 0 && !(cert.voters[i - 1] < cert.voters[i])) return false;  // dup/unsorted
        const std::uint64_t stake = stake_of(cert.voters[i]);
        if (stake == 0) return false;  // out-of-set voter ⇒ invalid cert
        voted += stake;
    }
    // (5) the tier's distinct-voter floor.
    if (cert.voters.size() < floor_count) return false;
    // (6) the tier's STRICT stake floor, recomputed — not trusted from the cert.
    //     A Nova cert relabelled Quasar dies here; a Quasar cert relabelled Nova
    //     only under-claims.
    if (voted <= stake_floor(cert.tier)) return false;

    // (7) CRYPTO: the aggregate signature verifies over the canonical message under
    //     the aggregate of the voters' pubkeys.
    //     PRECONDITION: each validator pubkey admitted to the set MUST have had its
    //     proof-of-possession verified upstream (P-chain admission). Aggregation over
    //     a common message is sound only under that assumption; this gate trusts the
    //     admitted set, exactly as the Go engine does.
    const std::vector<std::uint8_t> msg = canonical_vote_message(cert.position);
    std::vector<std::uint8_t> pks_flat;
    pks_flat.reserve(cert.voters.size() * 48);
    for (const auto& pk : cert.voters)
        pks_flat.insert(pks_flat.end(), pk.begin(), pk.end());
    return bls::fast_aggregate_verify(pks_flat.data(), cert.voters.size(),
                                      msg.data(), msg.size(), cert.aggregate_sig.data()) == 0;
}

}  // namespace lux::consensus
