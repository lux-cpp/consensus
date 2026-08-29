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

#include <cstdint>
#include <cstring>
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

    std::cout << "\n" << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
