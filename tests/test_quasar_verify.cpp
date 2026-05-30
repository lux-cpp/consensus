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

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
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

    std::cout << "\n" << paths.size() << " fixtures, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
