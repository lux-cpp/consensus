// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// canonical_message_parity_test.cpp — the KAT that PINS canonical_vote_message to
// its Go original (engine/chain/cert.go, canonicalVoteMessageFor). The signed
// message is what a signature COMMITS TO: if a byte, a width, an endianness, or a
// field ORDER here diverges from Go, a C++ node and a Go node would sign/verify
// DIFFERENT messages over the "same" position — a silent finality split. So the
// layout is nailed to a hand-built golden vector, byte for byte, and cross-checked
// field by field at its exact offset.
//
// GOLDEN (226 bytes, "vote/v2", QuorumCertVersion 3), constructed here from LITERAL
// bytes — independent of the production put_be16/32/64 helpers, so an endianness
// bug in either is caught. The OUTER block_id/parent_id are set to DIFFERENT fills
// than the inner canonical ids, proving the outer ids never enter the message:
//
//   off  len  field                  bytes
//   0    18   "LUX/chain/vote/v2\0"   domain tag (NUL-terminated)
//   18   2    version                00 03              (BE, = kQuorumCertVersion)
//   20   1    qc_type                01                 (= kQCFinality)
//   21   32   chain_id               C1 ×32
//   53   8    height                 01 02 03 04 05 06 07 08  (BE)
//   61   4    round                  0A 0B 0C 0D        (BE)
//   65   32   canonical_id           B2 ×32   (inner; NOT the outer block_id 0x11)
//   97   32   parent_canonical_id    A3 ×32   (inner; NOT the outer parent_id 0x22)
//   129  32   execution_state_root   E5 ×32
//   161  32   payload_root           D6 ×32
//   193  32   validator_set_root     54 ×32
//   225  1    accept                 01                 (0x01 accept | 0x00 reject)

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
    std::printf("canonical_vote_message is byte-for-byte the Go 226-byte v2 layout, or this fails\n\n");

    // ── The position with KNOWN values on ALL axes. The outer block_id/parent_id
    //    get DIFFERENT fills than the inner canonical ids, so the message can only
    //    match the golden if it binds the INNER ids and drops the outer ones. ──────
    VotePosition pos{};
    pos.chain_id.fill(0xC1);
    pos.height = 0x0102030405060708ULL;
    pos.round  = 0x0A0B0C0Du;
    pos.block_id.fill(0x11);              // OUTER envelope — must NOT appear in the message
    pos.parent_id.fill(0x22);             // OUTER envelope — must NOT appear
    pos.canonical_id.fill(0xB2);          // inner execution id — THIS is signed
    pos.parent_canonical_id.fill(0xA3);   // inner parent id
    pos.execution_state_root.fill(0xE5);
    pos.payload_root.fill(0xD6);
    pos.validator_set_root.fill(0x54);

    // ── The golden vector, built from literal bytes (NOT the production helpers) ──
    std::vector<std::uint8_t> want;
    const char tag[] = "LUX/chain/vote/v2\x00";
    want.insert(want.end(), tag, tag + sizeof(tag) - 1);          // 18: tag + NUL
    want.push_back(0x00); want.push_back(0x03);                   // version BE = 3
    want.push_back(0x01);                                         // qc_type = QCFinality
    fill32(want, 0xC1);                                           // chain_id
    for (std::uint8_t b : {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}) want.push_back(b);  // height BE
    for (std::uint8_t b : {0x0A,0x0B,0x0C,0x0D}) want.push_back(b);                      // round  BE
    fill32(want, 0xB2);                                           // canonical_id (inner, not 0x11)
    fill32(want, 0xA3);                                           // parent_canonical_id (inner, not 0x22)
    fill32(want, 0xE5);                                           // execution_state_root
    fill32(want, 0xD6);                                           // payload_root
    fill32(want, 0x54);                                           // validator_set_root
    want.push_back(0x01);                                        // accept = true

    check(want.size() == 226, "golden vector is exactly 226 bytes");

    // ── [1] the produced ACCEPT message equals the golden vector, byte for byte ──
    const std::vector<std::uint8_t> got = canonical_vote_message(pos);
    check(got.size() == 226, "canonical_vote_message is 226 bytes (18+2+1+32+8+4+32+32+32+32+32+1)");
    check(got == want, "canonical_vote_message == Go golden vector (byte-for-byte)");

    // ── [2] domain tag prefix (17 chars + a terminating NUL at offset 17) ────────
    const std::string kTag = "LUX/chain/vote/v2";
    bool tag_ok = got.size() >= 18 && got[17] == 0x00;
    for (std::size_t i = 0; i < kTag.size() && tag_ok; ++i)
        tag_ok = got[i] == static_cast<std::uint8_t>(kTag[i]);
    check(tag_ok, "domain tag prefix is \"LUX/chain/vote/v2\\0\" (NUL-terminated)");

    // ── [3] every field sits at its exact offset (width + order + endianness) ────
    check(got[18] == 0x00 && got[19] == 0x03, "version at [18..20) is BE 0x0003 (kQuorumCertVersion)");
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
    bool canon_ok = true;  for (std::size_t i = 65;  i < 97;  ++i) canon_ok  &= got[i] == 0xB2;
    check(canon_ok,  "canonical_id at [65..97) is the INNER 0xB2 ×32 (NOT outer block_id 0x11)");
    bool pcanon_ok = true; for (std::size_t i = 97;  i < 129; ++i) pcanon_ok &= got[i] == 0xA3;
    check(pcanon_ok, "parent_canonical_id at [97..129) is the INNER 0xA3 ×32 (NOT outer parent_id 0x22)");
    bool esr_ok = true;    for (std::size_t i = 129; i < 161; ++i) esr_ok    &= got[i] == 0xE5;
    check(esr_ok,    "execution_state_root at [129..161) is 0xE5 ×32");
    bool pr_ok = true;     for (std::size_t i = 161; i < 193; ++i) pr_ok     &= got[i] == 0xD6;
    check(pr_ok,     "payload_root at [161..193) is 0xD6 ×32");
    bool root_ok = true;   for (std::size_t i = 193; i < 225; ++i) root_ok   &= got[i] == 0x54;
    check(root_ok,   "validator_set_root at [193..225) is 0x54 ×32");
    check(got[225] == 0x01, "accept byte at [225] is 0x01 (ACCEPT)");
    // the outer ids must appear NOWHERE (no 0x11 / 0x22 byte anywhere in the message)
    bool no_outer = true;
    for (std::uint8_t b : got) if (b == 0x11 || b == 0x22) { no_outer = false; break; }
    check(no_outer, "outer block_id(0x11)/parent_id(0x22) appear NOWHERE — excluded from the signed message");

    // ── [4] accept vs reject differ ONLY in the last byte ────────────────────────
    const std::vector<std::uint8_t> rej = canonical_vote_message_for(pos, false);
    check(rej.size() == 226, "reject message is also 226 bytes");
    check(rej[225] == 0x00, "reject accept-byte at [225] is 0x00 (REJECT)");
    bool prefix_identical = got.size() == rej.size();
    for (std::size_t i = 0; i < 225 && prefix_identical; ++i) prefix_identical = got[i] == rej[i];
    check(prefix_identical, "accept and reject share the identical first 225 bytes");
    check(got[225] != rej[225], "accept and reject differ ONLY in the trailing accept byte");

    // ── [5] canonical-id FALLBACK: a caller that sets only the OUTER block_id (no
    //   canonical_id) signs the outer id in the canonical slot — byte-identical to
    //   Go's `if canonicalID == Empty { canonicalID = BlockID }`, and to the
    //   pre-split message for an unwrapped block. Backward-safe. ──────────────────
    VotePosition bare{};
    bare.block_id.fill(0x42);   // outer only; canonical_id left Empty → must fall back to 0x42
    bare.height = 7;
    const std::vector<std::uint8_t> bare_msg = canonical_vote_message(bare);
    bool bare_ok = bare_msg.size() == 226;
    for (std::size_t i = 65; i < 97 && bare_ok; ++i)   bare_ok = bare_msg[i] == 0x42;  // canonical_id ⇐ block_id
    for (std::size_t i = 21; i < 53 && bare_ok; ++i)   bare_ok = bare_msg[i] == 0x00;  // chain_id Empty
    for (std::size_t i = 97; i < 225 && bare_ok; ++i)  bare_ok = bare_msg[i] == 0x00;  // parent + roots Empty
    check(bare_ok, "bare position: canonical_id slot falls back to block_id (0x42), rest Empty");

    std::printf("------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== CANONICAL MESSAGE PARITY: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== CANONICAL MESSAGE PARITY: PASS — 226-byte v2 layout matches Go byte-for-byte ====\n");
    return 0;
}
