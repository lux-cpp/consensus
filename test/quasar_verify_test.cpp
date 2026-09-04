// Copyright (c) 2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Quasar witness BLS verification — parity tests vs Go fixtures.
//
// Fixtures are produced by `TestDumpWitnessFixtures` in
// luxfi/consensus/protocol/quasar/witness_fixtures_test.go. See that
// file for the canonical wire layout.

#include "lux/quasar.h"
#include "lux/quasar.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <blst.h>

#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    std::string name;
    bool expect_valid {false};
    std::vector<std::uint8_t> group_key;  // 48 bytes
    std::vector<std::uint8_t> msg;
    std::vector<std::uint8_t> sig;        // 96 bytes
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
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    }
    return true;
}

Fixture load_fixture(const fs::path& path) {
    Fixture f;
    f.name = path.filename().string();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open " + path.string());
    }
    char magic[4];
    in.read(magic, 4);
    if (std::memcmp(magic, "QWFX", 4) != 0) {
        throw std::runtime_error(f.name + ": bad magic");
    }
    std::uint32_t abi = 0;
    if (!read_u32_le(in, abi) || abi != 1) {
        throw std::runtime_error(f.name + ": bad ABI version");
    }
    std::uint8_t flag[4];
    in.read(reinterpret_cast<char*>(flag), 4);
    f.expect_valid = (flag[0] == 0x01);
    f.group_key.resize(48);
    in.read(reinterpret_cast<char*>(f.group_key.data()), 48);
    std::uint64_t msg_len = 0;
    if (!read_u64_le(in, msg_len)) {
        throw std::runtime_error(f.name + ": cannot read msg_len");
    }
    f.msg.resize(static_cast<std::size_t>(msg_len));
    if (msg_len > 0) {
        in.read(reinterpret_cast<char*>(f.msg.data()), static_cast<std::streamsize>(msg_len));
    }
    f.sig.resize(96);
    in.read(reinterpret_cast<char*>(f.sig.data()), 96);
    if (!in) {
        throw std::runtime_error(f.name + ": truncated");
    }
    return f;
}

std::string status_name(lux::quasar::Status s) {
    switch (s) {
        case lux::quasar::Status::Ok:           return "Ok";
        case lux::quasar::Status::ErrInvalid:   return "ErrInvalid";
        case lux::quasar::Status::ErrSignature: return "ErrSignature";
        case lux::quasar::Status::ErrVerify:    return "ErrVerify";
    }
    return "?";
}

int run_one(const Fixture& f) {
    using namespace lux::quasar;

    std::cout << "[fixture] " << f.name
              << " expect=" << (f.expect_valid ? "VALID" : "INVALID")
              << " msg_len=" << f.msg.size() << "\n";

    // Path 1: C++ surface (WitnessVerifier).
    Status cxx_st = Status::ErrInvalid;
    try {
        WitnessVerifier v(std::span<const std::uint8_t, kPubKeyLen>(f.group_key.data(), kPubKeyLen));
        cxx_st = v.verify(
            std::span<const std::uint8_t>(f.msg.data(), f.msg.size()),
            std::span<const std::uint8_t, kSignatureLen>(f.sig.data(), kSignatureLen));
    } catch (const std::exception& e) {
        std::cout << "  cxx ctor threw: " << e.what() << "\n";
        cxx_st = Status::ErrSignature;
    }

    // Path 2: free function (verify_once).
    const Status one_st = verify_once(
        std::span<const std::uint8_t, kPubKeyLen>(f.group_key.data(), kPubKeyLen),
        std::span<const std::uint8_t>(f.msg.data(), f.msg.size()),
        std::span<const std::uint8_t, kSignatureLen>(f.sig.data(), kSignatureLen));

    // Path 3: C ABI (lux_quasar_witness_verify).
    const lux_quasar_status c_st = lux_quasar_witness_verify(
        f.group_key.data(), f.group_key.size(),
        f.msg.empty() ? nullptr : f.msg.data(), f.msg.size(),
        f.sig.data(), f.sig.size());

    std::cout << "  cxx=" << status_name(cxx_st)
              << " one=" << status_name(one_st)
              << " c=" << lux_quasar_status_str(c_st) << "\n";

    const bool cxx_ok = (cxx_st == Status::Ok);
    const bool one_ok = (one_st == Status::Ok);
    const bool c_ok   = (c_st   == LUX_QUASAR_OK);

    if (cxx_ok != one_ok || cxx_ok != c_ok) {
        std::cerr << "  FAIL: paths disagree (cxx=" << cxx_ok
                  << " one=" << one_ok << " c=" << c_ok << ")\n";
        return 1;
    }
    if (cxx_ok != f.expect_valid) {
        std::cerr << "  FAIL: result " << (cxx_ok ? "VALID" : "INVALID")
                  << " ≠ expected " << (f.expect_valid ? "VALID" : "INVALID") << "\n";
        return 1;
    }
    return 0;
}

// A point ON the curve but OUTSIDE the prime-order subgroup. The G1 cofactor is
// enormous, so all but a vanishing fraction of curve points are outside it: walk
// candidate x values and take the first that decompresses. blst's uncompress
// validates the curve equation and NOT the subgroup — which is exactly why the
// subgroup check is a separate clause, and why it has to be exercised with a
// point that gets past the first one. RFC 9380 §4.1: without it an attacker can
// present a point that pairs to the identity.
std::vector<std::uint8_t> off_subgroup_g1() {
    std::vector<std::uint8_t> enc(48, 0);
    for (std::uint32_t x = 1; x < 4096; ++x) {
        enc.assign(48, 0);
        enc[47] = static_cast<std::uint8_t>(x);
        enc[46] = static_cast<std::uint8_t>(x >> 8);
        enc[0] |= 0x80;  // compressed form
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

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (ok) { std::cout << "    ok   " << what << "\n"; return; }
    ++g_fail;
    std::cout << "    FAIL " << what << "\n";
}

// Everything the witness surface refuses, and the reason it gives. A verifier
// that answered Ok for any of these would admit a round nobody signed; one that
// answered the WRONG refusal would tell a caller to retry what it should drop.
void refusals(const Fixture& good) {
    using namespace lux::quasar;

    const auto pk_span = [](const std::vector<std::uint8_t>& v) {
        return std::span<const std::uint8_t, kPubKeyLen>(v.data(), kPubKeyLen);
    };
    const auto sig_span = [](const std::vector<std::uint8_t>& v) {
        return std::span<const std::uint8_t, kSignatureLen>(v.data(), kSignatureLen);
    };
    const auto msg_span = [](const std::vector<std::uint8_t>& v) {
        return std::span<const std::uint8_t>(v.data(), v.size());
    };

    std::cout << "\n[refusals] the group key\n";
    {
        std::vector<std::uint8_t> identity(48, 0);
        identity[0] = 0xC0;                      // the Zcash compressed identity
        const std::vector<std::uint8_t> zeros(48, 0);
        std::vector<std::uint8_t> garbage(48, 0xAB);
        const std::vector<std::uint8_t> off = off_subgroup_g1();

        // The identity public key verifies a signature over ANY message, so it is
        // refused where the key is bound rather than at every later verification.
        const auto ctor_throws = [&](const std::vector<std::uint8_t>& k, const std::string& what) {
            bool threw = false;
            try { WitnessVerifier v(pk_span(k)); } catch (const std::invalid_argument&) { threw = true; }
            check(threw, what);
        };
        ctor_throws(identity, "the identity group key is refused at construction");
        ctor_throws(zeros, "and so is the all-zero encoding of it");
        ctor_throws(garbage, "a group key that is not a curve point is refused");
        ctor_throws(off, "a curve point outside the prime-order subgroup is refused");

        // verify_once takes the same four decisions without building a verifier,
        // and must reach the same verdict — two entry points, one rule.
        check(verify_once(pk_span(identity), msg_span(good.msg), sig_span(good.sig)) == Status::ErrSignature,
              "verify_once refuses the identity group key");
        check(verify_once(pk_span(zeros), msg_span(good.msg), sig_span(good.sig)) == Status::ErrSignature,
              "verify_once refuses the all-zero group key");
        check(verify_once(pk_span(garbage), msg_span(good.msg), sig_span(good.sig)) == Status::ErrSignature,
              "verify_once refuses a group key that is not a point");
        check(verify_once(pk_span(off), msg_span(good.msg), sig_span(good.sig)) == Status::ErrSignature,
              "verify_once refuses an off-subgroup group key");

        // The identity test is a PREFIX test — 0xC0 then forty-seven zeros. A key
        // that merely starts 0xC0 is not the identity and must fall through to the
        // real decode, or every key in that eighth of the encoding space would be
        // refused as if it were the zero key.
        std::vector<std::uint8_t> c0_prefixed(48, 0);
        c0_prefixed[0] = 0xC0;
        c0_prefixed[47] = 0x01;
        bool threw = false;
        try { WitnessVerifier v(pk_span(c0_prefixed)); } catch (const std::invalid_argument& e) {
            threw = true;
            check(std::string(e.what()).find("identity") == std::string::npos,
                  "a 0xC0-prefixed non-identity key is not mistaken for the identity");
        }
        check(threw, "…it is refused on its own merits — these bytes are not a point");
    }

    std::cout << "\n[refusals] the signature\n";
    {
        WitnessVerifier v(pk_span(good.group_key));
        check(v.verify(msg_span(good.msg), sig_span(good.sig)) == Status::Ok,
              "the fixture's own signature verifies — every refusal below is one edit from it");

        std::vector<std::uint8_t> garbage(96, 0xCD);
        check(v.verify(msg_span(good.msg), sig_span(garbage)) == Status::ErrSignature,
              "a signature that is not a curve point is ErrSignature, not ErrVerify");

        const std::vector<std::uint8_t> off = off_subgroup_g2();
        check(v.verify(msg_span(good.msg), sig_span(off)) == Status::ErrSignature,
              "an on-curve signature outside G2 is refused before any pairing");

        std::vector<std::uint8_t> flipped = good.sig;
        flipped[95] ^= 0x01;
        const Status st = v.verify(msg_span(good.msg), sig_span(flipped));
        check(st == Status::ErrVerify || st == Status::ErrSignature,
              "a signature with one bit flipped does not verify");

        std::vector<std::uint8_t> other_msg = good.msg;
        other_msg.push_back(0x00);
        check(v.verify(msg_span(other_msg), sig_span(good.sig)) == Status::ErrVerify,
              "a signature over a different message is ErrVerify — it decoded, it just is not this round");

        // The dynamic-extent overload is the same rule with the width checked
        // rather than carried by the type: a caller holding a runtime-sized buffer
        // must not be able to hand over 95 bytes and be told the round is bad.
        check(v.verify(msg_span(good.msg), std::span<const std::uint8_t>(good.sig.data(), 95)) ==
                  Status::ErrInvalid,
              "a short signature is a malformed CALL, not a failed verification");
        check(v.verify(msg_span(good.msg), std::span<const std::uint8_t>(good.sig.data(), 96)) ==
                  Status::Ok,
              "and at the right width it is the same verify");

        // verify_once takes the signature's two decode clauses independently of the
        // verifier, so both must be exercised through it too — one rule, two doors.
        check(verify_once(pk_span(good.group_key), msg_span(good.msg), sig_span(garbage)) ==
                  Status::ErrSignature,
              "verify_once refuses a signature that is not a curve point");
        check(verify_once(pk_span(good.group_key), msg_span(good.msg), sig_span(off)) ==
                  Status::ErrSignature,
              "and one on the curve but outside G2");
        check(verify_once(pk_span(good.group_key), msg_span(other_msg), sig_span(good.sig)) ==
                  Status::ErrVerify,
              "and reaches the pairing for a signature over another message");
    }

    std::cout << "\n[refusals] a moved-from verifier is inert\n";
    {
        WitnessVerifier a(pk_span(good.group_key));
        check(a.backend() == Backend::Cpu, "the verify path is CPU — Gpu is reserved, not default");
        WitnessVerifier b(std::move(a));
        check(b.verify(msg_span(good.msg), sig_span(good.sig)) == Status::Ok,
              "the moved-TO verifier holds the group key and still verifies");
        check(a.verify(msg_span(good.msg), sig_span(good.sig)) == Status::ErrInvalid,  // NOLINT
              "and the moved-FROM one answers ErrInvalid rather than reading freed memory");

        WitnessVerifier c(pk_span(good.group_key));
        c = std::move(b);
        check(c.verify(msg_span(good.msg), sig_span(good.sig)) == Status::Ok,
              "move-assignment carries the key and frees the target's own");
        check(b.verify(msg_span(good.msg), sig_span(good.sig)) == Status::ErrInvalid,  // NOLINT
              "leaving the source inert");

        // Self-move. The guard is `this != &other`; without it the assignment
        // deletes its own impl and then adopts the pointer it just freed, and the
        // next verify reads freed memory. Routed through a pointer because a
        // syntactic self-move is a compiler diagnostic, not a runtime one — and it
        // is the runtime behaviour that has to hold.
        WitnessVerifier* same = &c;
        c = std::move(*same);
        check(c.verify(msg_span(good.msg), sig_span(good.sig)) == Status::Ok,
              "a verifier moved onto itself still holds its own group key");
    }

    std::cout << "\n[refusals] the C ABI\n";
    {
        const std::uint8_t* pk = good.group_key.data();
        const std::uint8_t* sg = good.sig.data();
        const std::uint8_t* mg = good.msg.empty() ? nullptr : good.msg.data();
        const std::size_t   ml = good.msg.size();

        check(lux_quasar_witness_verify(pk, 48, mg, ml, sg, 96) == LUX_QUASAR_OK,
              "the ABI verifies the fixture");
        check(lux_quasar_witness_verify(nullptr, 48, mg, ml, sg, 96) == LUX_QUASAR_ERR_INVALID,
              "a null group key is an invalid argument, never a verdict");
        check(lux_quasar_witness_verify(pk, 48, mg, ml, nullptr, 96) == LUX_QUASAR_ERR_INVALID,
              "and so is a null signature");
        check(lux_quasar_witness_verify(pk, 47, mg, ml, sg, 96) == LUX_QUASAR_ERR_INVALID,
              "a group key of the wrong width is refused before it is read");
        check(lux_quasar_witness_verify(pk, 48, mg, ml, sg, 95) == LUX_QUASAR_ERR_INVALID,
              "and a signature of the wrong width likewise");
        check(lux_quasar_witness_verify(pk, 48, nullptr, 1, sg, 96) == LUX_QUASAR_ERR_INVALID,
              "a null message with a non-zero length is a caller bug, not an empty message");
        // A genuinely empty message is legal and is a different thing from a null
        // one: it decodes, it just is not what this signature was made over.
        check(lux_quasar_witness_verify(pk, 48, nullptr, 0, sg, 96) == LUX_QUASAR_ERR_VERIFY,
              "an empty message is verified and rejected on the pairing, not on the arguments");

        // The status strings are the ABI's other half — a cgo caller reads these.
        check(std::string(lux_quasar_status_str(LUX_QUASAR_OK)) == "ok" &&
                  std::string(lux_quasar_status_str(LUX_QUASAR_ERR_INVALID)) == "invalid argument" &&
                  std::string(lux_quasar_status_str(LUX_QUASAR_ERR_SIG)) ==
                      "signature or pubkey decode failed" &&
                  std::string(lux_quasar_status_str(LUX_QUASAR_ERR_VERIFY)) == "signature did not verify",
              "every status the ABI can return has its own name");
        check(std::string(lux_quasar_status_str(static_cast<lux_quasar_status>(99))) == "unknown",
              "and a status from a newer ABI reads as unknown rather than as one of these");
        check(lux_quasar_abi_version() == LUX_QUASAR_ABI_VERSION,
              "the ABI reports the version this header was compiled against");
    }
}

}  // namespace

int main(int argc, char** argv) {
    fs::path dir;
    if (argc >= 2) {
        dir = argv[1];
    } else if (const char* env = std::getenv("QUASAR_FIXTURES")) {
        dir = env;
    } else {
        dir = fs::path(__FILE__).parent_path().parent_path() / "testdata";
    }
    if (!fs::is_directory(dir)) {
        std::cerr << "fixture dir not found: " << dir << "\n";
        std::cerr << "regenerate with: QUASAR_DUMP=" << dir
                  << " go test -count=1 -run TestDumpWitnessFixtures "
                  << "github.com/luxfi/consensus/protocol/quasar\n";
        return 2;
    }

    std::cout << "ABI version: " << lux_quasar_abi_version() << "\n";
    std::cout << "Fixture dir: " << dir << "\n\n";

    std::vector<fs::path> paths;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() &&
            entry.path().filename().string().rfind("witness_", 0) == 0 &&
            entry.path().extension() == ".bin") {
            paths.push_back(entry.path());
        }
    }
    if (paths.empty()) {
        std::cerr << "no witness_*.bin fixtures in " << dir << "\n";
        return 2;
    }
    std::sort(paths.begin(), paths.end());

    int failures = 0;
    int verify_ok_count = 0;
    for (const auto& p : paths) {
        Fixture f = load_fixture(p);
        failures += run_one(f);
        if (f.expect_valid) ++verify_ok_count;
    }

    // ---- Perf microbench. Two columns:
    //   verify_once   — cold-path (pk decode + subgroup check each call)
    //   WitnessVerifier::verify — hot-path (pk pre-parsed at construction)
    // Hot-path is the realistic cgo cost: the Go bridge constructs a
    // verifier per validator-set, reuses it for every finalised round.
    if (verify_ok_count > 0) {
        Fixture bench;
        for (const auto& p : paths) {
            Fixture f = load_fixture(p);
            if (f.expect_valid) { bench = std::move(f); break; }
        }

        // Cold path
        {
            const auto start = std::chrono::steady_clock::now();
            std::size_t iters = 0;
            while (true) {
                for (int k = 0; k < 64; ++k) {
                    const auto st = lux::quasar::verify_once(
                        std::span<const std::uint8_t, lux::quasar::kPubKeyLen>(bench.group_key.data(), lux::quasar::kPubKeyLen),
                        std::span<const std::uint8_t>(bench.msg.data(), bench.msg.size()),
                        std::span<const std::uint8_t, lux::quasar::kSignatureLen>(bench.sig.data(), lux::quasar::kSignatureLen));
                    if (st != lux::quasar::Status::Ok) {
                        std::cerr << "bench cold: unexpected non-OK\n";
                        return 1;
                    }
                    ++iters;
                }
                if (std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(250)) break;
            }
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - start).count();
            std::cout << "\n[bench cold] verify_once:        "
                      << iters << " iters in " << (ns / 1'000'000) << " ms — "
                      << (static_cast<double>(ns) / 1000.0 / iters) << " us, "
                      << static_cast<std::uint64_t>(iters * 1e9 / ns) << " ops/s\n";
        }

        // Hot path
        {
            lux::quasar::WitnessVerifier v(
                std::span<const std::uint8_t, lux::quasar::kPubKeyLen>(bench.group_key.data(), lux::quasar::kPubKeyLen));
            const auto start = std::chrono::steady_clock::now();
            std::size_t iters = 0;
            while (true) {
                for (int k = 0; k < 64; ++k) {
                    const auto st = v.verify(
                        std::span<const std::uint8_t>(bench.msg.data(), bench.msg.size()),
                        std::span<const std::uint8_t, lux::quasar::kSignatureLen>(bench.sig.data(), lux::quasar::kSignatureLen));
                    if (st != lux::quasar::Status::Ok) {
                        std::cerr << "bench hot: unexpected non-OK\n";
                        return 1;
                    }
                    ++iters;
                }
                if (std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(250)) break;
            }
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - start).count();
            std::cout << "[bench hot]  WitnessVerifier:    "
                      << iters << " iters in " << (ns / 1'000'000) << " ms — "
                      << (static_cast<double>(ns) / 1000.0 / iters) << " us, "
                      << static_cast<std::uint64_t>(iters * 1e9 / ns) << " ops/s\n";
        }
    }

    // The fixtures say what a good round looks like. The refusal table says what
    // everything else looks like, one edit at a time from that same good round.
    for (const auto& p : paths) {
        Fixture f = load_fixture(p);
        if (f.expect_valid) { refusals(f); break; }
    }
    failures += g_fail;

    std::cout << "\n" << paths.size() << " fixtures, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
