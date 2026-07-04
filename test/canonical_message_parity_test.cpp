// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// canonical_message_parity_test.cpp — the KAT that PINS canonical_vote_message to
// its Go original (engine/chain/quorum_cert.go, canonicalVoteMessageFor). The
// signed message is what a signature COMMITS TO: if a byte, a width, an
// endianness, or a field ORDER here diverges from Go, a C++ node and a Go node
// would sign/verify DIFFERENT messages over the "same" position — a silent
// finality split. So the layout is nailed to a hand-built golden vector, byte for
// byte, and cross-checked field by field at its exact offset.
//
// GOLDEN (162 bytes), constructed here from LITERAL bytes — independent of the
// production put_be16/32/64 helpers, so an endianness bug in either is caught:
//
//   off  len  field                bytes
//   0    18   "LUX/chain/vote/v1\0" domain tag (NUL-terminated)
//   18   2    version              00 02              (BE, = kQuorumCertVersion)
//   20   1    qc_type              01                 (= kQCFinality)
//   21   32   chain_id             C1 ×32
//   53   8    height               01 02 03 04 05 06 07 08  (BE)
//   61   4    round                0A 0B 0C 0D        (BE)
//   65   32   block_id             B2 ×32
//   97   32   parent_id            A3 ×32
//   129  32   validator_set_root   54 ×32
//   161  1    accept               01                 (0x01 accept | 0x00 reject)

#include "lux/consensus2/quorum_cert_engine.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace lux::consensus2;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

// Append 32 copies of `b` — a whole 32-byte axis at a known fill.
void fill32(std::vector<std::uint8_t>& v, std::uint8_t b) {
    for (int i = 0; i < 32; ++i) v.push_back(b);
}

}  // namespace

int main() {
    std::printf("============== consensus2 — CANONICAL MESSAGE PARITY (KAT vs Go) ==============\n");
    std::printf("canonical_vote_message is byte-for-byte the Go 162-byte layout, or this fails\n\n");

    // ── The position with KNOWN non-trivial values on ALL six axes ───────────────
    VotePosition pos{};
    pos.chain_id.fill(0xC1);
    pos.height = 0x0102030405060708ULL;
    pos.round  = 0x0A0B0C0Du;
    pos.block_id.fill(0xB2);
    pos.parent_id.fill(0xA3);
    pos.validator_set_root.fill(0x54);

    // ── The golden vector, built from literal bytes (NOT the production helpers) ──
    std::vector<std::uint8_t> want;
    const char tag[] = "LUX/chain/vote/v1\x00";
    want.insert(want.end(), tag, tag + sizeof(tag) - 1);          // 18: tag + NUL
    want.push_back(0x00); want.push_back(0x02);                   // version BE = 2
    want.push_back(0x01);                                         // qc_type = QCFinality
    fill32(want, 0xC1);                                           // chain_id
    for (std::uint8_t b : {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}) want.push_back(b);  // height BE
    for (std::uint8_t b : {0x0A,0x0B,0x0C,0x0D}) want.push_back(b);                      // round  BE
    fill32(want, 0xB2);                                           // block_id
    fill32(want, 0xA3);                                           // parent_id
    fill32(want, 0x54);                                           // validator_set_root
    want.push_back(0x01);                                        // accept = true

    check(want.size() == 162, "golden vector is exactly 162 bytes");

    // ── [1] the produced ACCEPT message equals the golden vector, byte for byte ──
    const std::vector<std::uint8_t> got = canonical_vote_message(pos);
    check(got.size() == 162, "canonical_vote_message is 162 bytes (18+2+1+32+8+4+32+32+32+1)");
    check(got == want, "canonical_vote_message == Go golden vector (byte-for-byte)");

    // ── [2] domain tag prefix (17 chars + a terminating NUL at offset 17) ────────
    const std::string kTag = "LUX/chain/vote/v1";
    bool tag_ok = got.size() >= 18 && got[17] == 0x00;
    for (std::size_t i = 0; i < kTag.size() && tag_ok; ++i)
        tag_ok = got[i] == static_cast<std::uint8_t>(kTag[i]);
    check(tag_ok, "domain tag prefix is \"LUX/chain/vote/v1\\0\" (NUL-terminated)");

    // ── [3] every field sits at its exact offset (width + order + endianness) ────
    check(got[18] == 0x00 && got[19] == 0x02, "version at [18..20) is BE 0x0002 (kQuorumCertVersion)");
    check(got[18] == std::uint8_t(kQuorumCertVersion >> 8) && got[19] == std::uint8_t(kQuorumCertVersion),
          "version bytes track the kQuorumCertVersion constant");
    check(got[20] == 0x01 && got[20] == kQCFinality, "qc_type at [20] is kQCFinality (0x01)");
    bool chain_ok = true; for (std::size_t i = 21; i < 53; ++i) chain_ok &= got[i] == 0xC1;
    check(chain_ok, "chain_id at [21..53) is 0xC1 ×32");
    // height BE at [53..61)
    check(got[53]==0x01 && got[54]==0x02 && got[55]==0x03 && got[56]==0x04 &&
          got[57]==0x05 && got[58]==0x06 && got[59]==0x07 && got[60]==0x08,
          "height at [53..61) is big-endian 0x0102030405060708");
    // round BE at [61..65)
    check(got[61]==0x0A && got[62]==0x0B && got[63]==0x0C && got[64]==0x0D,
          "round at [61..65) is big-endian 0x0A0B0C0D");
    bool block_ok = true;  for (std::size_t i = 65;  i < 97;  ++i) block_ok  &= got[i] == 0xB2;
    check(block_ok,  "block_id at [65..97) is 0xB2 ×32");
    bool parent_ok = true; for (std::size_t i = 97;  i < 129; ++i) parent_ok &= got[i] == 0xA3;
    check(parent_ok, "parent_id at [97..129) is 0xA3 ×32");
    bool root_ok = true;   for (std::size_t i = 129; i < 161; ++i) root_ok   &= got[i] == 0x54;
    check(root_ok,   "validator_set_root at [129..161) is 0x54 ×32");
    check(got[161] == 0x01, "accept byte at [161] is 0x01 (ACCEPT)");

    // ── [4] accept vs reject differ ONLY in the last byte ────────────────────────
    const std::vector<std::uint8_t> rej = canonical_vote_message_for(pos, false);
    check(rej.size() == 162, "reject message is also 162 bytes");
    check(rej[161] == 0x00, "reject accept-byte at [161] is 0x00 (REJECT)");
    bool prefix_identical = got.size() == rej.size();
    for (std::size_t i = 0; i < 161 && prefix_identical; ++i) prefix_identical = got[i] == rej[i];
    check(prefix_identical, "accept and reject share the identical first 161 bytes");
    check(got[161] != rej[161], "accept and reject differ ONLY in the trailing accept byte");

    // ── [5] the all-Empty position (only block_id/height set) is backward-safe ───
    //   A caller that sets none of the new axes signs a message byte-identical to Go
    //   with those fields Empty — same length, same tag, zero-filled axes.
    VotePosition bare{};
    bare.block_id.fill(0x42);
    bare.height = 7;
    const std::vector<std::uint8_t> bare_msg = canonical_vote_message(bare);
    bool bare_ok = bare_msg.size() == 162;
    for (std::size_t i = 21; i < 53 && bare_ok; ++i)   bare_ok = bare_msg[i] == 0x00;  // chain_id Empty
    for (std::size_t i = 61; i < 65 && bare_ok; ++i)   bare_ok = bare_msg[i] == 0x00;  // round 0
    for (std::size_t i = 97; i < 161 && bare_ok; ++i)  bare_ok = bare_msg[i] == 0x00;  // parent + set-root Empty
    check(bare_ok, "a bare position (new axes unset) yields the Empty-filled 162-byte message");

    std::printf("------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== CANONICAL MESSAGE PARITY: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== CANONICAL MESSAGE PARITY: PASS — 162-byte layout matches Go byte-for-byte ====\n");
    return 0;
}
