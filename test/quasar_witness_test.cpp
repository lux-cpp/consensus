// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness aggregator — sanity tests for the share aggregation
// path. Full byte-for-byte parity with Go's t-of-n Lagrange-weighted
// aggregator requires a separate fixture dump (the Lagrange scaling
// happens on the Go side); for now we verify:
//   1. n=1 aggregation returns the single sig unchanged.
//   2. Each share input that fails subgroup check is rejected.
//   3. Aggregating a known-valid signature once produces a 96-byte
//      output that is itself a valid G2 point.
//
// The verify-after-aggregate parity (Go aggregator output == C++
// aggregator output) is exercised end-to-end by witness_04 of the
// verify-test suite: that fixture's signature is precisely the
// output of Go's aggregator, and the C++ verifier verifies it.

#include "lux/quasar.h"
#include "lux/quasar.hpp"

#include <blst.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    std::string name;
    std::vector<std::uint8_t> group_key;
    std::vector<std::uint8_t> msg;
    std::vector<std::uint8_t> sig;
};

bool read_u32_le(std::ifstream& in, std::uint32_t& out) {
    std::uint8_t b[4];
    if (!in.read(reinterpret_cast<char*>(b), 4)) return false;
    out = static_cast<std::uint32_t>(b[0]) |
          (static_cast<std::uint32_t>(b[1]) << 8) |
          (static_cast<std::uint32_t>(b[2]) << 16) |
          (static_cast<std::uint32_t>(b[3]) << 24);
    return true;
}

bool read_u64_le(std::ifstream& in, std::uint64_t& out) {
    std::uint8_t b[8];
    if (!in.read(reinterpret_cast<char*>(b), 8)) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    return true;
}

Fixture load(const fs::path& path) {
    Fixture f;
    f.name = path.filename().string();
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("open " + path.string());
    char magic[4];
    in.read(magic, 4);
    if (std::memcmp(magic, "QWFX", 4) != 0) throw std::runtime_error(f.name + ": bad magic");
    std::uint32_t abi = 0;
    if (!read_u32_le(in, abi) || abi != 1) throw std::runtime_error(f.name + ": bad abi");
    std::uint8_t flag[4];
    in.read(reinterpret_cast<char*>(flag), 4);
    f.group_key.resize(48);
    in.read(reinterpret_cast<char*>(f.group_key.data()), 48);
    std::uint64_t msg_len = 0;
    if (!read_u64_le(in, msg_len)) throw std::runtime_error(f.name + ": msg_len");
    f.msg.resize(static_cast<std::size_t>(msg_len));
    if (msg_len > 0) in.read(reinterpret_cast<char*>(f.msg.data()), static_cast<std::streamsize>(msg_len));
    f.sig.resize(96);
    in.read(reinterpret_cast<char*>(f.sig.data()), 96);
    if (!in) throw std::runtime_error(f.name + ": truncated");
    return f;
}

void pack_share(std::vector<std::uint8_t>& out, std::uint32_t index,
                const std::vector<std::uint8_t>& sig96) {
    if (sig96.size() != 96) throw std::runtime_error("pack_share: sig not 96 bytes");
    out.push_back(static_cast<std::uint8_t>((index >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((index >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((index >> 8)  & 0xFF));
    out.push_back(static_cast<std::uint8_t>( index        & 0xFF));
    out.insert(out.end(), sig96.begin(), sig96.end());
}

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (ok) { std::cout << "    ok   " << what << "\n"; return; }
    ++g_fail;
    std::cout << "    FAIL " << what << "\n";
}

// An on-curve G2 point outside the prime-order subgroup: the aggregator's second
// clause is a subgroup check, and a point that fails the FIRST clause cannot
// exercise it. blst's uncompress validates the curve equation only, so walking
// candidate x values and keeping the first that decompresses gives one.
std::vector<std::uint8_t> off_subgroup_g1() {
    std::vector<std::uint8_t> enc(48, 0);
    for (std::uint32_t x = 1; x < 4096; ++x) {
        enc.assign(48, 0);
        enc[47] = static_cast<std::uint8_t>(x);
        enc[46] = static_cast<std::uint8_t>(x >> 8);
        enc[0] |= 0x80;
        blst_p1_affine a;
        if (blst_p1_uncompress(&a, enc.data()) == BLST_SUCCESS && !blst_p1_affine_in_g1(&a))
            return enc;
    }
    throw std::runtime_error("no off-subgroup G1 candidate found");
}

std::vector<std::uint8_t> off_subgroup_g2() {
    std::vector<std::uint8_t> enc(96, 0);
    for (std::uint32_t x = 1; x < 4096; ++x) {
        enc.assign(96, 0);
        enc[95] = static_cast<std::uint8_t>(x);
        enc[94] = static_cast<std::uint8_t>(x >> 8);
        enc[0] |= 0x80;
        blst_p2_affine a;
        if (blst_p2_uncompress(&a, enc.data()) == BLST_SUCCESS && !blst_p2_affine_in_g2(&a))
            return enc;
    }
    throw std::runtime_error("no off-subgroup G2 candidate found");
}

}  // namespace

int main(int argc, char** argv) {
    fs::path dir;
    if (argc >= 2) dir = argv[1];
    else if (const char* env = std::getenv("QUASAR_FIXTURES")) dir = env;
    else dir = fs::path(__FILE__).parent_path().parent_path() / "testdata";

    if (!fs::is_directory(dir)) {
        std::cerr << "fixture dir not found: " << dir << "\n";
        return 2;
    }

    const Fixture single = load(dir / "witness_01_single_signer.bin");
    const Fixture three  = load(dir / "witness_04_threshold_3of3.bin");

    using namespace lux::quasar;

    int failures = 0;

    // ---- Test 1: n=1 aggregation returns the input sig unchanged.
    // blst's aggregator initialises from the first sig and adds zero
    // others; the compressed output should be byte-identical to the
    // input.
    {
        std::vector<std::uint8_t> packed;
        pack_share(packed, 0, single.sig);
        WitnessAggregator agg(std::span<const std::uint8_t, kPubKeyLen>(single.group_key.data(), kPubKeyLen));
        std::uint8_t out[96] = {};
        const Status st = agg.aggregate(
            std::span<const std::uint8_t>(packed.data(), packed.size()),
            1,
            std::span<std::uint8_t, kSignatureLen>(out, kSignatureLen));
        if (st != Status::Ok) {
            std::cerr << "[test1] aggregate failed: " << static_cast<int>(st) << "\n";
            ++failures;
        } else if (std::memcmp(out, single.sig.data(), 96) != 0) {
            std::cerr << "[test1] n=1 aggregate != input\n";
            ++failures;
        } else {
            std::cout << "[test1] n=1 aggregate byte-identical to input — PASS\n";
        }
    }

    // ---- Test 2: aggregating a tampered share is rejected (subgroup
    // or decode failure).
    {
        std::vector<std::uint8_t> tampered = single.sig;
        tampered.back() ^= 0x01;
        std::vector<std::uint8_t> packed;
        pack_share(packed, 0, tampered);
        WitnessAggregator agg(std::span<const std::uint8_t, kPubKeyLen>(single.group_key.data(), kPubKeyLen));
        std::uint8_t out[96] = {};
        const Status st = agg.aggregate(
            std::span<const std::uint8_t>(packed.data(), packed.size()),
            1,
            std::span<std::uint8_t, kSignatureLen>(out, kSignatureLen));
        if (st == Status::Ok) {
            std::cerr << "[test2] aggregator accepted tampered sig\n";
            ++failures;
        } else {
            std::cout << "[test2] tampered share rejected — PASS\n";
        }
    }

    // ---- Test 3: aggregating the 3-of-3 threshold sig as a single
    // input must round-trip (it's already an aggregated G2 point), and
    // the result must verify against the threshold group key via the
    // C ABI hot path. This is the end-to-end parity proof: Go produced
    // this signature via its aggregator; we re-aggregate (n=1, copy)
    // and then C++ verifies it.
    {
        std::vector<std::uint8_t> packed;
        pack_share(packed, 0, three.sig);
        WitnessAggregator agg(std::span<const std::uint8_t, kPubKeyLen>(three.group_key.data(), kPubKeyLen));
        std::uint8_t out[96] = {};
        const Status st = agg.aggregate(
            std::span<const std::uint8_t>(packed.data(), packed.size()),
            1,
            std::span<std::uint8_t, kSignatureLen>(out, kSignatureLen));
        if (st != Status::Ok) {
            std::cerr << "[test3] aggregate failed\n"; ++failures;
        } else {
            const lux_quasar_status vst = lux_quasar_witness_verify(
                three.group_key.data(), three.group_key.size(),
                three.msg.data(), three.msg.size(),
                out, 96);
            if (vst != LUX_QUASAR_OK) {
                std::cerr << "[test3] verify on re-aggregated 3-of-3 cert FAILED: "
                          << lux_quasar_status_str(vst) << "\n";
                ++failures;
            } else {
                std::cout << "[test3] 3-of-3 threshold cert verified end-to-end — PASS\n";
            }
        }
    }

    // ---- The aggregator's refusals. An aggregate is the sum of what it was
    // handed, so a share it should not have added is a signature nobody made.
    {
        using PK = std::span<const std::uint8_t, kPubKeyLen>;
        const auto pk_of = [](const std::vector<std::uint8_t>& v) { return PK(v.data(), kPubKeyLen); };
        std::uint8_t out[96] = {};
        const auto out_span = [&] { return std::span<std::uint8_t, kSignatureLen>(out, kSignatureLen); };

        std::cout << "\n[refusals] the group key the aggregator is bound to\n";
        {
            std::vector<std::uint8_t> identity(48, 0);
            identity[0] = 0xC0;
            const std::vector<std::uint8_t> zeros(48, 0);
            const std::vector<std::uint8_t> garbage(48, 0xAB);
            const auto ctor_throws = [&](const std::vector<std::uint8_t>& k, const std::string& what) {
                bool threw = false;
                try { WitnessAggregator a(pk_of(k)); } catch (const std::invalid_argument&) { threw = true; }
                check(threw, what);
            };
            ctor_throws(identity, "the identity group key is refused at construction");
            ctor_throws(zeros, "and so is the all-zero encoding of it");
            ctor_throws(garbage, "a group key that is not a curve point is refused");
            ctor_throws(off_subgroup_g1(),
                        "a curve point outside the prime-order subgroup is refused");

            // The identity test is a PREFIX test. A key that merely starts 0xC0 is
            // not the identity and must fall through to the real decode, or an
            // eighth of the encoding space would be refused as the zero key.
            std::vector<std::uint8_t> c0_prefixed(48, 0);
            c0_prefixed[0] = 0xC0;
            c0_prefixed[47] = 0x01;
            bool threw = false;
            try { WitnessAggregator a(pk_of(c0_prefixed)); } catch (const std::invalid_argument& e) {
                threw = true;
                check(std::string(e.what()).find("identity") == std::string::npos,
                      "a 0xC0-prefixed non-identity key is not mistaken for the identity");
            }
            check(threw, "…it is refused on its own merits — these bytes are not a point");
        }

        std::cout << "\n[refusals] the share buffer\n";
        {
            std::vector<std::uint8_t> packed;
            pack_share(packed, 0, single.sig);
            WitnessAggregator agg(pk_of(single.group_key));

            check(agg.aggregate(std::span<const std::uint8_t>(packed.data(), packed.size()), 1,
                                out_span()) == Status::Ok,
                  "one well-formed share aggregates — every refusal below is one edit from it");
            check(agg.aggregate(std::span<const std::uint8_t>(packed.data(), packed.size()), 0,
                                out_span()) == Status::ErrInvalid,
                  "aggregating nothing is an invalid call, not an empty signature");
            check(agg.aggregate(std::span<const std::uint8_t>(packed.data(), packed.size()), 2,
                                out_span()) == Status::ErrInvalid,
                  "a count that does not match the buffer is refused before it is read past");
            check(agg.aggregate(std::span<const std::uint8_t>(packed.data(), packed.size() - 1), 1,
                                out_span()) == Status::ErrInvalid,
                  "and a share record one byte short likewise");

            // The second clause: a point that decompresses but is not in G2. Adding
            // it would put a component of unknown order into the sum.
            std::vector<std::uint8_t> off_packed;
            pack_share(off_packed, 7, off_subgroup_g2());
            check(agg.aggregate(std::span<const std::uint8_t>(off_packed.data(), off_packed.size()), 1,
                                out_span()) == Status::ErrSignature,
                  "an on-curve share outside G2 is refused, not summed");

            // Two shares, the second bad: the aggregator must refuse the WHOLE
            // aggregate rather than return the partial sum it had built.
            std::vector<std::uint8_t> mixed;
            pack_share(mixed, 0, single.sig);
            pack_share(mixed, 1, std::vector<std::uint8_t>(96, 0xCD));
            check(agg.aggregate(std::span<const std::uint8_t>(mixed.data(), mixed.size()), 2,
                                out_span()) == Status::ErrSignature,
                  "one bad share among good ones refuses the whole aggregate");

            // Two GOOD shares: the sum path, which the n=1 case never takes. The
            // result must be a point in its own right — an aggregate that is not on
            // the curve is one no verifier can ever accept — and it must depend on
            // BOTH shares, which is the whole difference between summing and
            // returning the first one.
            std::vector<std::uint8_t> two;
            pack_share(two, 0, single.sig);
            pack_share(two, 1, three.sig);
            check(agg.aggregate(std::span<const std::uint8_t>(two.data(), two.size()), 2,
                                out_span()) == Status::Ok,
                  "two well-formed shares aggregate");
            check(std::memcmp(out, single.sig.data(), 96) != 0 &&
                      std::memcmp(out, three.sig.data(), 96) != 0,
                  "…into a point that is neither of them — the shares are SUMMED, not picked");
            {
                blst_p2_affine a;
                check(blst_p2_uncompress(&a, out) == BLST_SUCCESS && blst_p2_affine_in_g2(&a),
                      "…and the sum is itself a point of G2");
            }
            // Order must not matter: point addition is commutative, and two nodes
            // collecting the same shares in different orders must produce the same
            // aggregate or the certificate they build is not the same certificate.
            std::vector<std::uint8_t> swapped;
            pack_share(swapped, 1, three.sig);
            pack_share(swapped, 0, single.sig);
            std::uint8_t out2[96] = {};
            check(agg.aggregate(std::span<const std::uint8_t>(swapped.data(), swapped.size()), 2,
                                std::span<std::uint8_t, kSignatureLen>(out2, kSignatureLen)) ==
                      Status::Ok &&
                      std::memcmp(out, out2, 96) == 0,
                  "…and the same shares in the other order give the same aggregate");
        }

        std::cout << "\n[refusals] a moved-from aggregator is inert\n";
        {
            std::vector<std::uint8_t> packed;
            pack_share(packed, 0, single.sig);
            const auto shares = [&] { return std::span<const std::uint8_t>(packed.data(), packed.size()); };

            WitnessAggregator a(pk_of(single.group_key));
            check(a.backend() == Backend::Cpu, "aggregation runs on the CPU backend");
            WitnessAggregator b(std::move(a));
            check(b.aggregate(shares(), 1, out_span()) == Status::Ok,
                  "the moved-TO aggregator still aggregates");
            check(a.aggregate(shares(), 1, out_span()) == Status::ErrInvalid,  // NOLINT
                  "and the moved-FROM one answers ErrInvalid rather than reading freed memory");

            WitnessAggregator c(pk_of(single.group_key));
            c = std::move(b);
            check(c.aggregate(shares(), 1, out_span()) == Status::Ok,
                  "move-assignment carries the binding and frees the target's own");
            check(b.aggregate(shares(), 1, out_span()) == Status::ErrInvalid,  // NOLINT
                  "leaving the source inert");

            // Self-move: without the `this != &other` guard the assignment frees
            // its own binding and then adopts the freed pointer. Routed through a
            // pointer because a syntactic self-move is a compiler diagnostic, and
            // it is the runtime behaviour that has to hold.
            WitnessAggregator* same = &c;
            c = std::move(*same);
            check(c.aggregate(shares(), 1, out_span()) == Status::Ok,
                  "an aggregator moved onto itself still holds its own binding");
        }

        std::cout << "\n[refusals] the C ABI\n";
        {
            std::vector<std::uint8_t> packed;
            pack_share(packed, 0, single.sig);
            const std::uint8_t* pk = single.group_key.data();
            const std::uint8_t* sh = packed.data();

            check(lux_quasar_witness_aggregate(pk, 48, sh, 1, out) == LUX_QUASAR_OK,
                  "the ABI aggregates one share");
            check(std::memcmp(out, single.sig.data(), 96) == 0,
                  "and n=1 through the ABI is the same byte-identical copy");
            check(lux_quasar_witness_aggregate(nullptr, 48, sh, 1, out) == LUX_QUASAR_ERR_INVALID,
                  "a null group key is an invalid argument");
            check(lux_quasar_witness_aggregate(pk, 48, nullptr, 1, out) == LUX_QUASAR_ERR_INVALID,
                  "and so is a null share buffer");
            check(lux_quasar_witness_aggregate(pk, 48, sh, 1, nullptr) == LUX_QUASAR_ERR_INVALID,
                  "and a null output buffer");
            check(lux_quasar_witness_aggregate(pk, 47, sh, 1, out) == LUX_QUASAR_ERR_INVALID,
                  "a group key of the wrong width is refused before it is read");
            check(lux_quasar_witness_aggregate(pk, 48, sh, 0, out) == LUX_QUASAR_ERR_INVALID,
                  "aggregating zero shares is refused rather than returning an empty point");

            // The ABI must not let a construction failure escape as an exception
            // into C. A group key that cannot be bound comes back as ErrSig.
            std::vector<std::uint8_t> identity(48, 0);
            identity[0] = 0xC0;
            check(lux_quasar_witness_aggregate(identity.data(), 48, sh, 1, out) == LUX_QUASAR_ERR_SIG,
                  "an unbindable group key crosses the ABI as a status, never as an exception");
        }
    }
    failures += g_fail;

    std::cout << "\n" << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
