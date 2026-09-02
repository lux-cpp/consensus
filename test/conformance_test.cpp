// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// conformance_test.cpp — consensus against the Go corpus.
//
// Go is the source of truth. scripts/oracle reads the values out of the running
// Go implementation and writes them here; this harness re-derives each one in
// C++ and demands byte equality. Nothing in this file states what the answer
// ought to be — the corpus does, and the corpus is regenerable.
//
// Four things are pinned, and they are exactly the four that were found to have
// silently drifted:
//   1. THE SIGNED MESSAGE — chain.CanonicalVoteMessage, 226 bytes, every axis.
//   2. THE DOMAIN TAG    — a signature is a hash-to-curve under a DST. Same key,
//                          same message, wrong tag ⇒ a signature the other side
//                          rejects. Pinned by pinning bls.Sign's output.
//   3. THE STAKE FLOORS  — config.TwoThirdsStakeFloor / HalfStakeFloor, to
//                          MaxUint64.
//   4. THE COMMITTEE     — NovaQuorum, NovaSignerFloor, TwoThirdsCount,
//                          AlphaForK (ceil).

#include "lux/consensus/bls.hpp"
#include "lux/consensus/cert.hpp"
#include "lux/consensus/quorum_cert_engine.hpp"
#include "lux/consensus/registration.hpp"  // CanonicalSet — the one way a Registry is seated
#include "lux/consensus/threshold.hpp"
#include "lux/consensus/wave.hpp"

#include "bls_signature.hpp"  // the eth2 POP surface — the domain trap, proven below

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace lux::consensus;

namespace {

int g_pass = 0, g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; return; }
    ++g_fail;
    std::printf("    FAIL: %s\n", what.c_str());
}

[[noreturn]] void die(const std::string& why) {
    std::printf("conformance: %s\n", why.c_str());
    std::exit(2);
}

// ── the corpus reader ────────────────────────────────────────────────────────
// The corpus schema is an ARRAY of FLAT objects whose values are strings,
// numbers or booleans. That is all of it, so this is all the reader: values are
// kept as their literal text (a uint64 near MaxUint64 must not go through a
// double), and anything nested is a corpus that does not match its schema —
// which is an error, not something to skip past.
using Row = std::map<std::string, std::string>;

class Reader {
public:
    explicit Reader(std::string s) : s_(std::move(s)) {}

    std::vector<Row> array() {
        std::vector<Row> rows;
        expect('[');
        skip();
        if (peek() == ']') { get(); return rows; }
        for (;;) {
            rows.push_back(object());
            skip();
            const char c = get();
            if (c == ']') break;
            if (c != ',') die("expected ',' or ']' in array");
        }
        return rows;
    }

private:
    std::string s_;
    std::size_t i_ = 0;

    void skip() { while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) ++i_; }
    char peek() { skip(); if (i_ >= s_.size()) die("unexpected end of corpus"); return s_[i_]; }
    char get() { const char c = peek(); ++i_; return c; }
    void expect(char c) { if (get() != c) die(std::string("expected '") + c + "'"); }

    std::string str() {
        expect('"');
        std::string out;
        for (;;) {
            if (i_ >= s_.size()) die("unterminated string");
            const char c = s_[i_++];
            if (c == '"') break;
            if (c == '\\') die("corpus strings carry no escapes by schema");
            out.push_back(c);
        }
        return out;
    }

    // A number, `true` or `false` — kept verbatim.
    std::string scalar() {
        skip();
        const std::size_t start = i_;
        while (i_ < s_.size() && s_[i_] != ',' && s_[i_] != '}' &&
               !std::isspace(static_cast<unsigned char>(s_[i_])))
            ++i_;
        if (i_ == start) die("empty scalar");
        return s_.substr(start, i_ - start);
    }

    Row object() {
        Row row;
        expect('{');
        skip();
        if (peek() == '}') { get(); return row; }
        for (;;) {
            const std::string key = str();
            skip();
            expect(':');
            skip();
            const char c = peek();
            if (c == '{' || c == '[') die("corpus objects are FLAT by schema: " + key);
            row[key] = (c == '"') ? str() : scalar();
            skip();
            const char n = get();
            if (n == '}') break;
            if (n != ',') die("expected ',' or '}' in object");
        }
        return row;
    }
};

std::vector<Row> load(const std::string& name) {
    const std::string path = std::string(CONSENSUS_VECTORS) + "/" + name;
    std::ifstream in(path, std::ios::binary);
    if (!in) die("cannot open " + path + " (regenerate: go run ./scripts/oracle -out vectors)");
    std::ostringstream buf;
    buf << in.rdbuf();
    return Reader(buf.str()).array();
}

const std::string& field(const Row& r, const std::string& key) {
    const auto it = r.find(key);
    if (it == r.end()) die("corpus row is missing field " + key);
    return it->second;
}

std::uint64_t u64(const Row& r, const std::string& key) {
    return std::strtoull(field(r, key).c_str(), nullptr, 10);
}

std::vector<std::uint8_t> unhex(const std::string& h) {
    if (h.size() % 2) die("odd-length hex in corpus");
    std::vector<std::uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::strtoul(h.substr(i, 2).c_str(), nullptr, 16)));
    return out;
}

std::string hex(const std::uint8_t* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { out.push_back(d[b[i] >> 4]); out.push_back(d[b[i] & 0xF]); }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(const Row& r, const std::string& key) {
    const std::vector<std::uint8_t> v = unhex(field(r, key));
    if (v.size() != N) die("corpus field " + key + " has the wrong width");
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = v[i];
    return out;
}

void banner(const char* what) { std::printf("\n-- %s\n", what); }

// ── 1. the signed vote message ───────────────────────────────────────────────
void vote_message() {
    banner("vote message — chain.CanonicalVoteMessage (226 bytes, every axis bound)");
    for (const Row& r : load("vote_message.json")) {
        const std::string name = field(r, "name");
        check(u64(r, "version") == kQuorumCertVersion, name + ": cert version matches Go");
        check(u64(r, "qc_type") == kQCFinality, name + ": qc type matches Go");

        VotePosition pos;
        pos.chain_id             = fixed<32>(r, "chain_id");
        pos.height               = u64(r, "height");
        pos.round                = static_cast<std::uint32_t>(u64(r, "round"));
        pos.block_id             = fixed<32>(r, "block_id");
        pos.parent_id            = fixed<32>(r, "parent_id");
        pos.canonical_id         = fixed<32>(r, "canonical_id");
        pos.parent_canonical_id  = fixed<32>(r, "parent_canonical_id");
        pos.execution_state_root = fixed<32>(r, "execution_state_root");
        pos.payload_root         = fixed<32>(r, "payload_root");
        pos.validator_set_root   = fixed<32>(r, "validator_set_root");

        const bool accept = field(r, "accept") == "true";
        const std::vector<std::uint8_t> msg = canonical_vote_message(pos, accept);
        check(msg.size() == 226, name + ": message is 226 bytes");
        check(hex(msg.data(), msg.size()) == field(r, "message"),
              name + ": message bytes are Go's, exactly");

        // The REJECT message must differ from the ACCEPT one in the last byte and
        // nowhere else: a reject signature can never be presented as an accept.
        const std::vector<std::uint8_t> other = canonical_vote_message(pos, !accept);
        check(other.size() == msg.size() && other.back() != msg.back() &&
                  std::equal(msg.begin(), msg.end() - 1, other.begin()),
              name + ": the accept byte, and only it, separates accept from reject");
    }
}

// ── 2. the domain separation tag ─────────────────────────────────────────────
void vote_signature() {
    banner("vote signature — the domain tag (bls.Sign, ..._RO_NUL_)");
    check(std::string(bls::kVoteDST) == "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
          "the consensus vote DST is Go's dstSignature");

    for (const Row& r : load("vote_signature.json")) {
        const std::string name = field(r, "name");
        const auto sk  = fixed<32>(r, "sk");
        const auto pk  = fixed<48>(r, "pk");
        const auto msg = unhex(field(r, "message"));

        std::array<std::uint8_t, 48> derived{};
        check(bls::sk_to_pk(sk.data(), derived.data()) == 0 && derived == pk,
              name + ": public key derives from the secret key as Go's does");

        std::array<std::uint8_t, 96> sig{};
        check(bls::sign(sk.data(), msg.data(), msg.size(), sig.data()) == 0,
              name + ": sign succeeds");
        check(hex(sig.data(), sig.size()) == field(r, "sig"),
              name + ": signature is byte-identical to Go's — the tag agrees");
        check(bls::verify(pk.data(), msg.data(), msg.size(), sig.data()) == 0,
              name + ": our verify accepts Go's signature");

        // THE TRAP, proven: the reused eth2 surface signs the SAME key over the SAME
        // message under ..._RO_POP_. It produces a different signature, and the two
        // domains reject each other. This is why consensus has its own surface.
        std::array<std::uint8_t, 96> pop{};
        check(cevm::crypto::bls::sign(sk.data(), msg.data(), msg.size(), pop.data()) == 0,
              name + ": the eth2 POP surface signs too");
        check(pop != sig, name + ": a POP-domain signature is NOT the consensus one");
        check(bls::verify(pk.data(), msg.data(), msg.size(), pop.data()) != 0,
              name + ": the consensus domain rejects a POP-domain signature");
    }
}

// ── 3. the stake floors ──────────────────────────────────────────────────────
void stake_floor() {
    banner("stake floors — config.TwoThirdsStakeFloor / HalfStakeFloor (to MaxUint64)");
    std::size_t n = 0;
    for (const Row& r : load("stake_floor.json")) {
        const std::uint64_t total = u64(r, "total");
        check(two_thirds_stake_floor(total) == u64(r, "two_thirds_floor"),
              "two_thirds_stake_floor(" + field(r, "total") + ")");
        check(half_stake_floor(total) == u64(r, "half_floor"),
              "half_stake_floor(" + field(r, "total") + ")");
        ++n;
    }
    std::printf("   %zu totals compared\n", n);
}

// ── 4. the committee thresholds ──────────────────────────────────────────────
void committee() {
    banner("committee — NovaQuorum / NovaSignerFloor / TwoThirdsCount / AlphaForK");
    for (const Row& r : load("committee.json")) {
        const auto n = static_cast<std::uint32_t>(u64(r, "n"));
        const std::string at = "(n=" + field(r, "n") + ")";
        check(nova_quorum(n) == u64(r, "nova_quorum"), "nova_quorum" + at);
        check(nova_signer_floor(n) == u64(r, "nova_signer_floor"), "nova_signer_floor" + at);
        check(two_thirds_count(n) == u64(r, "two_thirds_count"), "two_thirds_count" + at);
        // The truncation bug lived exactly here: trunc(21·0.69)=14 where Go
        // declares 15. ceil, and only ceil, reproduces the corpus.
        check(static_cast<std::uint64_t>(alpha_threshold(n, kConsensusSuperMajority)) ==
                  u64(r, "alpha_for_k"),
              "alpha_threshold" + at + " == Go AlphaForK (ceil, not truncation)");
    }
    // The wave a live set of n runs must agree with the same rule — at EVERY
    // size, not a five-point sample. This loop used to check {4,5,11,21,100},
    // and the ratio it checked round-tripped correctly for exactly those five
    // while overshooting by one for 33 other sizes in 4..1000. n=41 asked for
    // 29 where Go's quorum is 28, so a round sitting at 28/41 never decided,
    // and no test here could see it. A sample cannot establish "matches Go at
    // every committee size"; the sweep can.
    {
        std::uint32_t diverged = 0, first = 0;
        for (std::uint32_t n = 4; n <= 1000; ++n) {
            const WaveConfig cfg = WaveConfig::feasible(n);
            if (cfg.k != n || cfg.threshold != two_thirds_count(n)) {
                if (diverged == 0) first = n;
                ++diverged;
            }
        }
        check(diverged == 0,
              diverged == 0
                  ? std::string("feasible(n) is the strict-⅔ count for every n in 4..1000")
                  : "feasible(n) diverges at " + std::to_string(diverged) +
                        " sizes, first n=" + std::to_string(first));
    }
    // The size the ratio got wrong, named, so a regression is legible.
    check(WaveConfig::feasible(41).threshold == 28,
          "feasible(41) quorum is 28 — the size the float representation missed");
}


// ── 5. the certificate on the wire ───────────────────────────────────────────
// The layout, field by field, then the property that makes a certificate an
// identity: re-encoding what was decoded reproduces the bytes exactly. A codec
// that round-trips loosely gives one certificate many byte strings, and
// anything that treats those bytes as a name — a cache key, a dedup, a digest —
// can then be split by flipping a bit no field reads.
void cert_wire() {
    banner("certificate wire — chain.QuorumCert MarshalBinary/UnmarshalBinary (280-byte header)");
    for (const Row& r : load("cert_wire.json")) {
        const std::string name = field(r, "name");
        const std::vector<std::uint8_t> wire = unhex(field(r, "wire"));
        check(wire.size() == u64(r, "length"), name + ": the corpus length is the corpus bytes");

        Refusal why = Refusal::Wire;
        const std::optional<Cert> got = Cert::decode(wire.data(), wire.size(), why);
        if (!got) {
            check(false, name + ": decodes (refused: " + refusal_name(why) + ")");
            continue;
        }
        check(got->version == u64(r, "version"), name + ": version");
        check(got->role == u64(r, "qc_type"), name + ": role byte");
        check(static_cast<std::uint64_t>(got->tier) == u64(r, "tier"), name + ": tier");
        check(got->threshold == u64(r, "threshold"), name + ": threshold");
        check(got->votes.size() == u64(r, "vote_count"), name + ": vote count");

        const VotePosition& p = got->position;
        check(p.chain_id == fixed<32>(r, "chain_id"), name + ": chain id");
        check(p.height == u64(r, "height"), name + ": height");
        check(p.round == u64(r, "round"), name + ": round");
        check(p.block_id == fixed<32>(r, "block_id"), name + ": block id");
        check(p.parent_id == fixed<32>(r, "parent_id"), name + ": parent id");
        check(p.canonical_id == fixed<32>(r, "canonical_id"), name + ": canonical id");
        check(p.parent_canonical_id == fixed<32>(r, "parent_canonical_id"), name + ": parent canonical id");
        check(p.execution_state_root == fixed<32>(r, "execution_state_root"), name + ": execution state root");
        check(p.payload_root == fixed<32>(r, "payload_root"), name + ": payload root");
        check(p.validator_set_root == fixed<32>(r, "validator_set_root"), name + ": validator set root");

        const std::vector<std::uint8_t> again = got->encode();
        check(again == wire, name + ": re-encoding reproduces Go's bytes exactly");
    }
}

// ── 6. what the decoder must REFUSE ──────────────────────────────────────────
// These mutations are not in the corpus, because the corpus records what Go
// answers and Go's encoder cannot produce any of them. Refusal is the only
// sound answer to a byte string no encoder emits: admitting one would give a
// certificate a second name. Each mutation is derived from a corpus wire, so
// the cases stay in step with the layout rather than restating it.
void cert_wire_strict() {
    banner("certificate wire — fail-closed on what no encoder can produce");
    const std::vector<Row> rows = load("cert_wire.json");
    if (rows.empty()) die("cert_wire.json is empty");

    auto refused = [](const std::vector<std::uint8_t>& b) {
        Refusal why = Refusal::None;
        return !Cert::decode(b.data(), b.size(), why).has_value();
    };

    for (const Row& r : rows) {
        const std::string name = field(r, "name");
        const std::vector<std::uint8_t> wire = unhex(field(r, "wire"));

        // A trailing byte: the same certificate, a second byte string.
        std::vector<std::uint8_t> trailing = wire;
        trailing.push_back(0x00);
        check(refused(trailing), name + ": a trailing byte is refused");

        // Every truncation. A short read must never be filled in.
        bool every_prefix_refused = true;
        for (std::size_t n = 0; n < wire.size(); ++n) {
            if (!refused(std::vector<std::uint8_t>(wire.begin(), wire.begin() + std::ptrdiff_t(n))))
                every_prefix_refused = false;
        }
        check(every_prefix_refused, name + ": every truncation is refused");
    }

    // The rest need a certificate that HAS a vote to mutate. The header ends at
    // byte 280; the vote count is the four bytes before that.
    const std::vector<std::uint8_t> wire = unhex(field(rows.front(), "wire"));
    check(wire.size() > kCertHeaderLen, "the first corpus certificate carries a vote to mutate");

    // vote_count = 0xFFFFFFFF. Refused in O(1), before anything is allocated.
    std::vector<std::uint8_t> huge = wire;
    for (std::size_t i = kCertHeaderLen - 4; i < kCertHeaderLen; ++i) huge[i] = 0xFF;
    check(refused(huge), "an impossible vote count is refused before allocation");

    // The accept byte is one byte with two meanings. Anything else is a frame
    // the encoder cannot emit — and a decoder that folded 254 other values to
    // "true" would re-encode them as 1, which is the second-name defect.
    std::size_t accepted_junk = 0;
    for (unsigned v = 2; v < 256; ++v) {
        std::vector<std::uint8_t> junk = wire;
        junk[kCertHeaderLen + kNodeLen] = static_cast<std::uint8_t>(v);
        if (!refused(junk)) ++accepted_junk;
    }
    check(accepted_junk == 0, "the accept byte admits 0 and 1 and nothing else");
}

// ── 7. the finality predicate ────────────────────────────────────────────────
// Real committees, real BLS signatures, and Go's verdict for each — including
// every clause that REFUSES, which is where an implementation that "agrees"
// usually turns out not to.
void cert_verify() {
    banner("certificate predicate — chain.QuorumCert.Verify, clause by clause");
    std::size_t ok_rows = 0, refuse_rows = 0;
    for (const Row& r : load("cert_verify.json")) {
        const std::string name = field(r, "name");
        const std::size_t n = static_cast<std::size_t>(u64(r, "set_size"));
        const std::vector<std::uint8_t> nodes = unhex(field(r, "nodes"));
        const std::vector<std::uint8_t> pks = unhex(field(r, "pubkeys"));
        if (nodes.size() != n * kNodeLen || pks.size() != n * 48)
            die(name + ": the row's validator set is not " + std::to_string(n) + " entries wide");

        // The row's validator set, seated the ONE way a set is seated — through
        // the admitted set, because Registry has no other door. cert_verify names
        // no weights (the predicate counts votes against a threshold, not stake),
        // so each validator carries one unit: the smallest thing that is not a
        // phantom signer, and the honest spelling of "this corpus says nothing
        // about weight".
        CanonicalSet row;
        row.validators.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            Node id{};
            PubKey pk{};
            std::copy_n(nodes.begin() + std::ptrdiff_t(i * kNodeLen), kNodeLen, id.begin());
            std::copy_n(pks.begin() + std::ptrdiff_t(i * 48), 48, pk.begin());
            row.validators.push_back(CanonicalValidator{id, pk, 1});
        }
        row.total_weight = n;
        Registry set;
        if (!row.install(set)) die(name + ": Go's validator set did not seat");

        const std::vector<std::uint8_t> wire = unhex(field(r, "wire"));
        Refusal why = Refusal::Wire;
        const std::optional<Cert> cert = Cert::decode(wire.data(), wire.size(), why);
        if (!cert) {
            check(false, name + ": decodes (refused: " + std::string(refusal_name(why)) + ")");
            continue;
        }
        const std::string got = refusal_name(cert->verify(set));
        const std::string want = field(r, "expect");
        check(got == want, name + ": Verify answers " + want + (got == want ? "" : " (got " + got + ")"));
        (want == "ok" ? ok_rows : refuse_rows)++;
    }
    std::printf("   %zu certificates accepted, %zu refused — every clause of Verify\n", ok_rows, refuse_rows);
}

// ── 8. the two C++ certificates are two objects ──────────────────────────────
// Not a corpus check — an arithmetic one, stated here so it cannot be forgotten.
// QuorumCertEngine's certificate carries public keys and ONE aggregate
// signature; the portable certificate carries node ids and a signature per
// voter. They are different sizes, they hold different material, and neither
// can read the other's bytes. Reporting a timing of one beside the other
// languages' timing of the other would report the choice of algorithm as a
// language result.
void cert_shapes() {
    banner("the two certificate shapes — the aggregate gate and the portable witness");
    check(sizeof(PubKey) == 48 && sizeof(Node) == kNodeLen,
          "the aggregate cert is keyed by a 48-byte key; the portable one by a 20-byte node id");
    check(kCertHeaderLen == 280, "the portable header is 280 bytes — Go's qcHeaderSize");
    check(kCertVoteFixedLen == 25, "one vote record's fixed part is 25 bytes — Go's qcVoteFixed");
    // 313 = 280 header + 20 node + 1 accept + 4 length + 8 signature. The
    // smallest well-formed certificate, and the number the Go corpus records.
    check(kCertHeaderLen + kCertVoteFixedLen + 8 == 313,
          "the smallest well-formed certificate is 313 bytes, as Go records it");
}

// ── 9. the weighted finality decision ────────────────────────────────────────
//
// Everything above this asks what an implementation ENCODES. This asks what it
// DECIDES, which is a different question and the one that went unasked: a build
// carrying no weighted predicate at all reproduced every byte of this corpus and
// reported PASS. Each row states a validator set, the distinct signers a
// certificate carries and the rung it attests; Go recorded what its predicate
// decided, and this must decide the same.
//
// The engine is constructed from the validator set and NOTHING ELSE. Both tiers'
// distinct-voter floors are derived from that set, so the gate this harness drives
// is the gate a node runs — which is the whole point, and was the hole.
//
// This harness used to pass alpha = 1: the export floor was a constructor
// parameter then, and the reasoning was that the smallest legal value could never
// bind, so the C++ gate would ask exactly Go's question. It was right about Go and
// wrong about what a corpus is for. Go's export rung carried no count floor, C++'s
// carried whichever one the operator configured, and a harness built at alpha = 1
// is a harness that cannot see the difference — so the corpus reported agreement
// between two implementations that would decide the whale case differently on any
// real deployment, where alpha is floor(2n/3)+1 and not one. A conformance run
// must exercise the shipped configuration or it is conforming a configuration
// nothing runs.
//
// Signatures are real because they must be: the floors are checked before any
// pairing, so a refusal needs no key material, but nothing reaches ACCEPT
// without one. The keys are derived here rather than carried in the corpus —
// what is frozen is the decision, not a key ceremony, and the message the votes
// are cast over does not change any verdict.
struct Seat { std::array<std::uint8_t, 32> sk{}; PubKey pk{}; };

Seat seat_key(std::size_t i) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = static_cast<std::uint8_t>(i >> 8);
    seed[1] = static_cast<std::uint8_t>(i);
    for (std::size_t j = 2; j < 32; ++j) seed[j] = static_cast<std::uint8_t>(0x5A ^ (i + j));
    Seat s;
    if (bls::keygen(seed.data(), s.sk.data()) != 0) die("keygen");
    if (bls::sk_to_pk(s.sk.data(), s.pk.data()) != 0) die("sk_to_pk");
    return s;
}

void weighted_decision() {
    banner("weighted decision — the signer floor and the stake floor over a live set");

    std::size_t accepted = 0, refused = 0;
    for (const Row& r : load("decision.json")) {
        const std::string name = field(r, "name");
        const std::string rung = field(r, "rung");
        if (rung != "nova" && rung != "quasar")
            die(name + ": a certificate attests nova or quasar, not " + rung);
        const Tier tier = (rung == "nova") ? Tier::Nova : Tier::Quasar;

        const std::size_t n = static_cast<std::size_t>(u64(r, "set_size"));
        const std::size_t k = static_cast<std::size_t>(u64(r, "signer_count"));
        const std::vector<std::uint8_t> nodes   = unhex(field(r, "nodes"));
        const std::vector<std::uint8_t> weights = unhex(field(r, "weights"));
        const std::vector<std::uint8_t> signers = unhex(field(r, "signers"));
        if (nodes.size() != n * kNodeLen || weights.size() != n * 8 || signers.size() != k * kNodeLen)
            die(name + ": the row's set is not " + std::to_string(n) + " entries wide");

        // The RUNG's count floor, conformed on its own: a set of this size demands
        // this many distinct signers at this rung whatever the stake is. Nova's
        // saturates at three; Quasar's is the supermajority in seats and grows with
        // the set, and it is the clause that refuses a whale signing alone.
        const std::uint32_t want_floor =
            (tier == Tier::Quasar) ? two_thirds_count(static_cast<std::uint32_t>(n))
                                   : nova_signer_floor(static_cast<std::uint32_t>(n));
        check(want_floor == u64(r, "signer_floor"),
              name + ": the " + rung + " signer floor matches Go");

        // Seat the set: seat i holds the row's i-th weight under its own key.
        std::vector<Validator> vals;
        vals.reserve(n);
        std::vector<Seat> keys;
        keys.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            std::uint64_t w = 0;
            for (std::size_t b = 0; b < 8; ++b) w = (w << 8) | weights[i * 8 + b];
            keys.push_back(seat_key(i));
            vals.push_back(Validator{keys[i].pk, w});
        }

        QuorumCertEngine engine(vals);
        check(engine.total_stake() == u64(r, "total"), name + ": total stake matches Go");
        check(engine.stake_floor(tier) == u64(r, "stake_floor"),
              name + ": the " + rung + " stake floor matches Go");
        // And the floor the ENGINE derives is the one the corpus recorded — so the
        // decision below is reached through the same two numbers Go reached it by,
        // not through a configured value that happens to agree.
        check(engine.signer_floor(tier) == want_floor,
              name + ": the engine derives the " + rung + " signer floor from the set");

        // One block, one position. The decision does not depend on it, which the
        // corpus states outright, so the harness carries no position material.
        VotePosition pos{};
        if (!engine.submit(pos)) die(name + ": the block did not register");

        for (std::size_t j = 0; j < k; ++j) {
            // Which seat signed, by the node id the corpus names.
            std::size_t at = n;
            for (std::size_t i = 0; i < n; ++i)
                if (std::equal(signers.begin() + std::ptrdiff_t(j * kNodeLen),
                               signers.begin() + std::ptrdiff_t((j + 1) * kNodeLen),
                               nodes.begin() + std::ptrdiff_t(i * kNodeLen))) { at = i; break; }
            if (at == n) die(name + ": a signer is not in the set it is weighed against");

            const std::vector<std::uint8_t> msg = canonical_vote_message(pos);
            Signature sig{};
            if (bls::sign(keys[at].sk.data(), msg.data(), msg.size(), sig.data()) != 0) die("sign");
            if (engine.record_vote(pos.block_id, keys[at].pk, sig) != VoteResult::Recorded)
                die(name + ": a vote from the set was not recorded");
        }

        check(engine.voted_stake(pos.block_id) == u64(r, "voted"), name + ": the tally matches Go");

        const bool want = field(r, "expect") == "accept";
        const bool got  = engine.is_final(pos.block_id, tier);
        check(got == want, name + ": " + rung + " decides " + field(r, "expect") +
                               (got == want ? "" : std::string(" (got ") + (got ? "accept" : "reject") + ")"));
        (want ? accepted : refused)++;
    }
    std::printf("   %zu certificates accepted, %zu refused — on stake and on distinct signers\n",
                accepted, refused);
}

}  // namespace

int main() {
    std::printf("================== consensus — GO CONFORMANCE ==================\n");
    std::printf("corpus: %s\n", CONSENSUS_VECTORS);

    vote_message();
    vote_signature();
    stake_floor();
    committee();
    cert_wire();
    cert_wire_strict();
    cert_verify();
    weighted_decision();
    cert_shapes();

    std::printf("\n----------------------------------------------------------------\n");
    std::printf("checks: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) { std::printf("==== GO CONFORMANCE: FAIL ====\n"); return 1; }
    std::printf("==== GO CONFORMANCE: PASS — message, domain, floors, committee, certificate ====\n");
    return 0;
}
