// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

// oracle — emits the conformance corpus consensus is checked against.
//
// Go is the source of truth. Every value here is READ OUT of the running Go
// implementation (github.com/luxfi/consensus, github.com/luxfi/crypto), never
// restated: the vote message comes from chain.CanonicalVoteMessage, the
// signature from bls.Sign, the floors from config and engine/chain. If the Go
// encoder changes, the corpus changes, and the C++ harness that loads it fails —
// which is the whole point. A vector nobody can regenerate is a snapshot of a
// belief; this one is a measurement.
//
// Each file is a JSON ARRAY of FLAT objects whose values are strings or numbers.
// That is the entire schema, and it is deliberately the smallest thing a reader
// in any language can consume without a dependency.
//
//	go run ./scripts/oracle -out vectors
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/luxfi/consensus/config"
	"github.com/luxfi/consensus/engine/chain"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

func main() {
	out := flag.String("out", "vectors", "directory the corpus is written to")
	flag.Parse()

	write(*out, "vote_message.json", voteMessages())
	write(*out, "vote_signature.json", voteSignatures())
	write(*out, "stake_floor.json", stakeFloors())
	write(*out, "committee.json", committees())
	write(*out, "cert_wire.json", certWire())
	write(*out, "cert_verify.json", certVerify())
}

func write(dir, name string, rows []map[string]any) {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("  %s (%d rows)\n", name, len(rows))
}

// id builds a recognizable 32-byte id: every byte is `fill`, except the first,
// which is `tag`. Distinct per axis, so a field swapped with its neighbour in an
// implementation shows up as a byte diff rather than an accidental match.
func id(tag, fill byte) ids.ID {
	var v ids.ID
	for i := range v {
		v[i] = fill
	}
	v[0] = tag
	return v
}

// ---------------------------------------------------------------------------
// the signed vote message — chain.CanonicalVoteMessage
// ---------------------------------------------------------------------------

func row(name string, pos chain.VotePosition, accept bool, msg []byte) map[string]any {
	return map[string]any{
		"name":                 name,
		"chain_id":             hex.EncodeToString(pos.ChainID[:]),
		"height":               pos.Height,
		"round":                pos.Round,
		"block_id":             hex.EncodeToString(pos.BlockID[:]),
		"parent_id":            hex.EncodeToString(pos.ParentID[:]),
		"canonical_id":         hex.EncodeToString(pos.CanonicalID[:]),
		"parent_canonical_id":  hex.EncodeToString(pos.ParentCanonicalID[:]),
		"execution_state_root": hex.EncodeToString(pos.ExecutionStateRoot[:]),
		"payload_root":         hex.EncodeToString(pos.PayloadRoot[:]),
		"validator_set_root":   hex.EncodeToString(pos.ValidatorSetRoot[:]),
		"accept":               accept,
		"version":              chain.QuorumCertVersion,
		"qc_type":              uint8(chain.QCFinality),
		"message":              hex.EncodeToString(msg),
	}
}

func voteMessages() []map[string]any {
	// Fully populated: every axis distinct, so a transposed pair is visible.
	full := chain.VotePosition{
		ChainID:            id(0x01, 0xC1),
		Height:             0x0102030405060708,
		Round:              0x090A0B0C,
		BlockID:            id(0x02, 0xB1),
		ParentID:           id(0x03, 0xB2),
		CanonicalID:        id(0x04, 0xCA),
		ParentCanonicalID:  id(0x05, 0xCB),
		ExecutionStateRoot: id(0x06, 0xE5),
		PayloadRoot:        id(0x07, 0x70),
		ValidatorSetRoot:   id(0x08, 0x55),
	}
	// The degrade: a block with no inner/outer split leaves the canonical axes
	// empty, and the encoder binds the transport ids under the canonical slots.
	degrade := chain.VotePosition{
		ChainID:  id(0x11, 0xC1),
		Height:   7,
		Round:    3,
		BlockID:  id(0x12, 0xB1),
		ParentID: id(0x13, 0xB2),
	}
	// The zero position: every axis empty. Pins the encoder's shape alone.
	var zero chain.VotePosition

	return []map[string]any{
		row("full/accept", full, true, chain.CanonicalVoteMessage(full)),
		row("degrade_canonical_to_transport/accept", degrade, true, chain.CanonicalVoteMessage(degrade)),
		row("zero/accept", zero, true, chain.CanonicalVoteMessage(zero)),
	}
}

// ---------------------------------------------------------------------------
// the vote SIGNATURE — bls.Sign, i.e. the domain separation tag
// ---------------------------------------------------------------------------

// A message and a key are not enough to agree on a signature: the domain tag is
// part of the hash-to-curve. These rows pin the tag by pinning its output.
func voteSignatures() []map[string]any {
	pos := chain.VotePosition{
		ChainID:            id(0x01, 0xC1),
		Height:             42,
		Round:              1,
		BlockID:            id(0x02, 0xB1),
		ParentID:           id(0x03, 0xB2),
		CanonicalID:        id(0x04, 0xCA),
		ParentCanonicalID:  id(0x05, 0xCB),
		ExecutionStateRoot: id(0x06, 0xE5),
		PayloadRoot:        id(0x07, 0x70),
		ValidatorSetRoot:   id(0x08, 0x55),
	}
	msg := chain.CanonicalVoteMessage(pos)

	rows := make([]map[string]any, 0, 3)
	for i := 0; i < 3; i++ {
		raw := make([]byte, 32)
		for j := range raw {
			raw[j] = byte(0xA5 ^ (i*31 + j))
		}
		raw[0] = byte(i + 1) // never zero: a zero scalar is not a key
		sk, err := bls.SecretKeyFromBytes(raw)
		if err != nil {
			panic(err)
		}
		sig := bls.Sign(sk, msg)
		pk := bls.PublicFromSecretKey(sk)
		if !bls.Verify(pk, sig, msg) {
			panic("oracle: go self-verify failed")
		}
		rows = append(rows, map[string]any{
			"name":    fmt.Sprintf("vote_sig/%d", i),
			"sk":      hex.EncodeToString(bls.SecretKeyToBytes(sk)),
			"pk":      hex.EncodeToString(bls.PublicKeyToCompressedBytes(pk)),
			"message": hex.EncodeToString(msg),
			"sig":     hex.EncodeToString(bls.SignatureToBytes(sig)),
		})
	}
	return rows
}

// ---------------------------------------------------------------------------
// the stake floors — config.TwoThirdsStakeFloor / config.HalfStakeFloor
// ---------------------------------------------------------------------------

func stakeFloors() []map[string]any {
	totals := []uint64{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 21, 99, 100, 101,
		1 << 20, (1 << 62) + 1, math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64,
	}
	rows := make([]map[string]any, 0, len(totals))
	for _, t := range totals {
		rows = append(rows, map[string]any{
			"total":            t,
			"two_thirds_floor": config.TwoThirdsStakeFloor(t),
			"half_floor":       config.HalfStakeFloor(t),
		})
	}
	return rows
}

// ---------------------------------------------------------------------------
// the committee thresholds — engine/chain + config
// ---------------------------------------------------------------------------

func committees() []map[string]any {
	ns := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 20, 21, 22, 100, 1000}
	rows := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		rows = append(rows, map[string]any{
			"n":                         n,
			"nova_quorum":               chain.NovaQuorum(n),
			"nova_signer_floor":         chain.NovaSignerFloor(n),
			"equal_stake_supermajority": config.EqualStakeSupermajorityThreshold(n),
			"alpha_for_k":               config.AlphaForK(n),
		})
	}
	return rows
}
