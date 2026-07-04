// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// quorum_cert_engine.cpp — finality gate implementation. The RULE lives here;
// the CRYPTO is cevm::crypto::bls (blst-backed, never reinvented).

#include "lux/consensus2/quorum_cert_engine.hpp"

#include "bls_signature.hpp"  // cevm::crypto::bls — REUSED crypto core (luxcpp/crypto/bls)

#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace lux::consensus2 {

namespace {

// Big-endian append helpers — fixed-width so the message is length-free and a
// field can never be confused with its neighbour (canonical, like Go's layout).
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

// Domain tag, NUL-terminated as a hard role separator — byte-identical to the Go
// reference tag so the constructions are recognizably the same family.
constexpr char kDomainTag[] = "LUX/chain/vote/v1\x00";
constexpr std::size_t kDomainTagLen = sizeof(kDomainTag) - 1;  // includes the NUL, drops the C terminator

// Verify one validator's BLS signature over `msg`. Returns true IFF the signature
// is a valid ACCEPT signature by `voter`. cevm::crypto::bls::verify returns 0 on
// success, 1 on mismatch, <0 on decode error — anything non-zero is "not valid".
[[nodiscard]] bool bls_verify(const PubKey& voter,
                              const std::vector<std::uint8_t>& msg,
                              const Signature& sig) noexcept {
    return cevm::crypto::bls::verify(voter.data(), msg.data(), msg.size(), sig.data()) == 0;
}

}  // namespace

std::uint64_t two_thirds_stake_floor(std::uint64_t total) noexcept {
    const std::uint64_t q = total / 3;
    const std::uint64_t r = total % 3;
    std::uint64_t floor = 2 * q;
    if (r == 2) ++floor;  // floor(2r/3): r∈{0,1}→0, r==2→1
    return floor;
}

std::vector<std::uint8_t> canonical_vote_message_for(const VotePosition& pos, bool accept) {
    // Byte-for-byte the Go canonicalVoteMessageFor layout (162 bytes). Field ORDER
    // and endianness are load-bearing: they are what a signature commits to, and a
    // Go-signed vote must verify here and vice-versa.
    std::vector<std::uint8_t> buf;
    buf.reserve(kDomainTagLen + 2 + 1 + 32 + 8 + 4 + 32 + 32 + 32 + 1);
    buf.insert(buf.end(), kDomainTag, kDomainTag + kDomainTagLen);                     // domain + NUL
    put_be16(buf, kQuorumCertVersion);                                                 // version:2
    buf.push_back(kQCFinality);                                                        // qc_type:1
    buf.insert(buf.end(), pos.chain_id.begin(), pos.chain_id.end());                   // chain_id:32
    put_be64(buf, pos.height);                                                         // height:8
    put_be32(buf, pos.round);                                                          // round:4
    buf.insert(buf.end(), pos.block_id.begin(), pos.block_id.end());                   // block_id:32
    buf.insert(buf.end(), pos.parent_id.begin(), pos.parent_id.end());                 // parent_id:32
    buf.insert(buf.end(), pos.validator_set_root.begin(), pos.validator_set_root.end()); // validator_set_root:32
    buf.push_back(accept ? std::uint8_t{0x01} : std::uint8_t{0x00});                   // accept:1
    return buf;
}

QuorumCertEngine::QuorumCertEngine(std::vector<Validator> validators, std::uint32_t alpha)
    : total_stake_(0), alpha_(alpha) {
    if (validators.empty())
        throw std::invalid_argument("consensus2: empty validator set");
    if (alpha == 0)
        throw std::invalid_argument("consensus2: alpha (distinct-voter floor) is zero");
    if (alpha > validators.size())
        throw std::invalid_argument("consensus2: alpha exceeds validator count — quorum unreachable");

    for (const auto& v : validators) {
        if (v.stake == 0)
            throw std::invalid_argument("consensus2: in-set validator has zero stake");
        if (!validators_.emplace(v.pubkey, v.stake).second)
            throw std::invalid_argument("consensus2: duplicate validator pubkey");
        // Checked add: a wrapped total_stake_ would corrupt the 2/3 floor and is a
        // safety bug, not a config error. Fail-closed at construction instead.
        if (total_stake_ > UINT64_MAX - v.stake)
            throw std::invalid_argument("consensus2: total stake overflows uint64");
        total_stake_ += v.stake;
    }
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

    if (p.verified)
    {
        // The quorum is already verified. An extra vote joins only after its own
        // individual pairing passes, so the "every counted voter is verified"
        // invariant is preserved.
        if (!bls_verify(voter, p.message, sig)) return VoteResult::RejectedBadSignature;
        p.votes.emplace(voter, sig);
        p.voted_stake += stake;
        return VoteResult::Accepted;
    }

    // Pre-quorum: accept as a CANDIDATE with no per-vote pairing. BLS over the same
    // message aggregates, so verification is O(1) (one aggregate pairing), not O(α)
    // individual pairings — done once below the moment the quorum is reachable.
    p.votes.emplace(voter, sig);
    p.voted_stake += stake;

    if (p.votes.size() >= alpha_ && p.voted_stake > two_thirds_stake_floor(total_stake_))
    {
        if (batch_verify(p))
        {
            p.verified = true;       // ONE pairing certifies the whole quorum
        }
        else
        {
            evict_invalid(p);        // a forged candidate is here: drop it, verify survivors
            // Best-effort attribution: if THIS vote was the forged one the quorum
            // check just caught, report it (it has been evicted and never counted).
            if (p.votes.find(voter) == p.votes.end())
                return VoteResult::RejectedBadSignature;
        }
    }
    return VoteResult::Accepted;
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
    if (cevm::crypto::bls::aggregate_sigs(sigs.data(), p.votes.size(), agg.data()) != 0)
        return false;
    // Same canonical message for every voter ⇒ fast_aggregate_verify is one pairing.
    return cevm::crypto::bls::fast_aggregate_verify(
               pks.data(), p.votes.size(), p.message.data(), p.message.size(), agg.data()) == 0;
}

void QuorumCertEngine::evict_invalid(Pending& p) const {
    // The aggregate failed ⇒ ≥1 candidate sig is bad. Pay the O(α) individual
    // verify ONLY on this attack path; drop forged sigs and refund their stake.
    for (auto it = p.votes.begin(); it != p.votes.end();) {
        if (!bls_verify(it->first, p.message, it->second)) {
            p.voted_stake -= stake_of(it->first);
            it = p.votes.erase(it);
        } else {
            ++it;
        }
    }
    // Survivors are each individually verified; a quorum among them is genuine.
    if (p.votes.size() >= alpha_ && p.voted_stake > two_thirds_stake_floor(total_stake_))
        p.verified = true;
}

bool QuorumCertEngine::meets_quorum(const Pending& p) const noexcept {
    // FAIL-CLOSED: no stake model ⇒ cannot assert a supermajority.
    if (total_stake_ == 0) return false;
    // VERIFIED: a BLS check covering every counted voter has passed. An unverified
    // (e.g. forged) candidate can satisfy the count/stake floors but never this —
    // so it can never drive finality. Set only by the aggregate verify (or the
    // individual-verify fallback) in record_vote.
    if (!p.verified) return false;
    // Count quorum: α distinct voters.
    if (p.votes.size() < alpha_) return false;
    // STRICT stake supermajority: voted > floor(2/3·total). Both gates required.
    if (p.voted_stake <= two_thirds_stake_floor(total_stake_)) return false;
    return true;
}

bool QuorumCertEngine::is_final(const BlockId& block_id) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pending_.find(block_id);
    return it != pending_.end() && meets_quorum(it->second);
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

std::optional<QuorumCert> QuorumCertEngine::assemble_cert(const BlockId& block_id) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto pit = pending_.find(block_id);
    if (pit == pending_.end() || !meets_quorum(pit->second)) return std::nullopt;
    const Pending& p = pit->second;

    // votes is a std::map keyed by pubkey ⇒ iteration is already strictly-ascending
    // and distinct — exactly the canonical "strictly increasing voter" order.
    QuorumCert cert;
    cert.version   = kQuorumCertVersion;
    cert.type      = kQCFinality;
    cert.position  = p.pos;
    cert.threshold = alpha_;
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
    if (cevm::crypto::bls::aggregate_sigs(sigs_flat.data(), cert.voters.size(),
                                          cert.aggregate_sig.data()) != 0) {
        return std::nullopt;  // structurally impossible for verified inputs; fail closed
    }
    return cert;
}

bool QuorumCertEngine::verify_cert(const QuorumCert& cert) const {
    // (1) version + role.
    if (cert.version != kQuorumCertVersion || cert.type != kQCFinality) return false;
    // (2) threshold matches engine policy and is reachable.
    if (cert.threshold == 0 || cert.threshold != alpha_) return false;
    // (3) fail-closed on no stake model.
    if (total_stake_ == 0) return false;
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
    // (5) α distinct-voter floor.
    if (cert.voters.size() < cert.threshold) return false;
    // (6) STRICT 2/3 stake supermajority (recomputed, not trusted from the cert).
    if (voted <= two_thirds_stake_floor(total_stake_)) return false;

    // (7) CRYPTO: the aggregate signature verifies over the canonical message under
    //     the aggregate of the voters' pubkeys. POP ciphersuite ⇒ rogue-key-safe.
    //     PRECONDITION: each validator pubkey admitted to the set MUST have had its
    //     proof-of-possession verified upstream (P-chain admission). fast_aggregate_verify
    //     is rogue-key-safe ONLY under that assumption; this gate trusts the admitted set.
    const std::vector<std::uint8_t> msg = canonical_vote_message(cert.position);
    std::vector<std::uint8_t> pks_flat;
    pks_flat.reserve(cert.voters.size() * 48);
    for (const auto& pk : cert.voters)
        pks_flat.insert(pks_flat.end(), pk.begin(), pk.end());
    return cevm::crypto::bls::fast_aggregate_verify(
               pks_flat.data(), cert.voters.size(),
               msg.data(), msg.size(), cert.aggregate_sig.data()) == 0;
}

}  // namespace lux::consensus2
