// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// cert.go — the certificate corpus: the wire bytes of engine/chain.QuorumCert,
// and the verdict Go's Verify returns for each one.
//
// This is the section C++ could not check, because C++ had no certificate in
// this shape to check with. The rows are read out of the running Go
// implementation the same way every other section is: the bytes come from
// QuorumCert.MarshalBinary, the verdict from QuorumCert.Verify, and the
// signatures from bls.Sign — nothing here states what the answer ought to be.
//
// TWO FILES, because they pin two different things:
//
//   cert_wire.json    the LAYOUT. Every field at its offset, and the bytes that
//                     result. Signatures are recognizable filler, not real: a
//                     codec is checked by round-trip, and paying for BLS to
//                     check a byte offset would only make the corpus slower.
//   cert_verify.json  the PREDICATE. Real committees, real signatures, and one
//                     row per clause of Verify — including the clauses that
//                     REFUSE, which is where an implementation that "agrees"
//                     usually turns out not to.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/luxfi/consensus/engine/chain"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

// certPosition is the position every certificate row binds to: every axis
// non-zero and distinct, so a field read from the wrong offset shows up as a
// byte diff rather than as an accidental match.
func certPosition() chain.VotePosition {
	return chain.VotePosition{
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
}

// node is validator i's transport identity: be64(i+1) then zeros, so ids are
// strictly increasing in i and a committee is already in canonical order.
func node(i int) ids.NodeID {
	var n ids.NodeID
	binary.BigEndian.PutUint64(n[:8], uint64(i)+1)
	return n
}

// certKey derives validator i's key from its index — the same derivation the
// three benchmark legs use, so a corpus row and a benchmark run share a
// committee.
func certKey(i int) *bls.SecretKey {
	var ikm [32]byte
	binary.BigEndian.PutUint64(ikm[:8], uint64(i)+1)
	sk, err := bls.SecretKeyFromSeed(ikm[:])
	if err != nil {
		panic(err)
	}
	return sk
}

// certFields flattens a cert's header into the corpus's flat schema, so a
// reader in any language can check every axis landed at its offset without a
// nested parser.
func certFields(name string, c *chain.QuorumCert, wire []byte) map[string]any {
	p := c.Position
	return map[string]any{
		"name":                 name,
		"version":              c.Version,
		"qc_type":              uint8(c.Type),
		"tier":                 uint8(c.Tier),
		"threshold":            c.Threshold,
		"vote_count":           len(c.Votes),
		"chain_id":             hex.EncodeToString(p.ChainID[:]),
		"height":               p.Height,
		"round":                p.Round,
		"block_id":             hex.EncodeToString(p.BlockID[:]),
		"parent_id":            hex.EncodeToString(p.ParentID[:]),
		"canonical_id":         hex.EncodeToString(p.CanonicalID[:]),
		"parent_canonical_id":  hex.EncodeToString(p.ParentCanonicalID[:]),
		"execution_state_root": hex.EncodeToString(p.ExecutionStateRoot[:]),
		"payload_root":         hex.EncodeToString(p.PayloadRoot[:]),
		"validator_set_root":   hex.EncodeToString(p.ValidatorSetRoot[:]),
		"wire":                 hex.EncodeToString(wire),
		"length":               len(wire),
	}
}

func marshal(c *chain.QuorumCert) []byte {
	b, err := c.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// cert_wire.json — the layout
// ---------------------------------------------------------------------------

func certWire() []map[string]any {
	pos := certPosition()

	// One signer, an eight-byte signature: the smallest well-formed certificate,
	// and the row that pins the 280-byte header exactly (313 - 20 - 1 - 4 - 8).
	single := &chain.QuorumCert{
		Version: chain.QuorumCertVersion, Type: chain.QCFinality, Tier: chain.Nova,
		Position: pos, Threshold: 1,
		Votes: []chain.SignedVote{{NodeID: node(0), Accept: true, Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	}

	// Ragged signature lengths, so a decoder that assumes 96 bytes per vote
	// walks off its records instead of reading the next one.
	ragged := &chain.QuorumCert{
		Version: chain.QuorumCertVersion, Type: chain.QCFinality, Tier: chain.Quasar,
		Position: pos, Threshold: 3,
		Votes: []chain.SignedVote{
			{NodeID: node(0), Accept: true, Signature: make([]byte, 96)},
			{NodeID: node(1), Accept: true, Signature: []byte{0xAA}},
			{NodeID: node(2), Accept: true, Signature: []byte{}},
		},
	}
	for i := range ragged.Votes[0].Signature {
		ragged.Votes[0].Signature[i] = byte(0x40 + i)
	}

	// Every axis at zero. Pins the encoder's shape with no value to hide behind.
	var zero chain.VotePosition
	empty := &chain.QuorumCert{
		Version: chain.QuorumCertVersion, Type: chain.QCFinality, Tier: chain.Nova,
		Position: zero, Threshold: 1,
		Votes: []chain.SignedVote{{NodeID: ids.EmptyNodeID, Accept: false, Signature: nil}},
	}

	rows := []map[string]any{
		certFields("wire/single", single, marshal(single)),
		certFields("wire/ragged_signatures", ragged, marshal(ragged)),
		certFields("wire/zero_position_reject_vote", empty, marshal(empty)),
	}

	// Sixteen and a hundred voters with real 96-byte signatures: the shape a
	// live certificate actually has, and enough records that an off-by-one in
	// the vote loop cannot survive.
	for _, n := range []int{16, 100} {
		c := signedCert(n, uint32(n), chain.Quasar)
		rows = append(rows, certFields(fmt.Sprintf("wire/committee_%d", n), c, marshal(c)))
	}
	return rows
}

// ---------------------------------------------------------------------------
// cert_verify.json — the predicate
// ---------------------------------------------------------------------------

// signedCert builds a real committee of n validators, each signing ACCEPT over
// the shared position, and assembles their certificate.
func signedCert(n int, threshold uint32, tier chain.Finality) *chain.QuorumCert {
	pos := certPosition()
	msg := chain.CanonicalVoteMessage(pos)
	votes := make([]chain.SignedVote, 0, n)
	for i := 0; i < n; i++ {
		sk := certKey(i)
		votes = append(votes, chain.SignedVote{
			NodeID:    node(i),
			Accept:    true,
			Signature: bls.SignatureToBytes(bls.Sign(sk, msg)),
		})
	}
	return &chain.QuorumCert{
		Version: chain.QuorumCertVersion, Type: chain.QCFinality, Tier: tier,
		Position: pos, Threshold: threshold, Votes: votes,
	}
}

// registry resolves node ids to public keys the way a verifying node does.
type registry map[ids.NodeID]*bls.PublicKey

func (r registry) VerifyVote(n ids.NodeID, msg, sig []byte, _ uint64) bool {
	pk, ok := r[n]
	if !ok {
		return false
	}
	s, err := bls.SignatureFromBytes(sig)
	if err != nil {
		return false
	}
	return bls.Verify(pk, s, msg)
}

func registryFor(n int) registry {
	r := make(registry, n)
	for i := 0; i < n; i++ {
		r[node(i)] = bls.PublicFromSecretKey(certKey(i))
	}
	return r
}

// verdict names what Go's Verify answered, in the vocabulary every leg reports
// refusals in. A refusal Go can return and this does not name is a corpus that
// has fallen behind the implementation, so it panics rather than flattening an
// unknown error to a generic failure.
func verdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, chain.ErrQCVersion):
		return "version"
	case errors.Is(err, chain.ErrQCType):
		return "role"
	case errors.Is(err, chain.ErrQCUnknownTier):
		return "tier"
	case errors.Is(err, chain.ErrQCThresholdZero):
		return "threshold_zero"
	case errors.Is(err, chain.ErrQCNoVotes):
		return "no_votes"
	case errors.Is(err, chain.ErrQCNotStrictlyIncreasing):
		return "order"
	case errors.Is(err, chain.ErrQCVoteNotAccept):
		return "not_accept"
	case errors.Is(err, chain.ErrQCSigInvalid):
		return "signature"
	case errors.Is(err, chain.ErrQCBelowThreshold):
		return "below_threshold"
	}
	panic("oracle: Verify returned a refusal the corpus cannot name: " + err.Error())
}

// verifyRow records one committee, its certificate bytes, and Go's verdict.
// The public keys travel with the row so the reader builds the SAME validator
// set Go verified against — a set that resolves a different key is testing a
// different question.
func verifyRow(name string, c *chain.QuorumCert, n int, wire []byte) map[string]any {
	pks := make([]byte, 0, n*48)
	nodes := make([]byte, 0, n*20)
	for i := 0; i < n; i++ {
		pk := bls.PublicKeyToCompressedBytes(bls.PublicFromSecretKey(certKey(i)))
		pks = append(pks, pk...)
		id := node(i)
		nodes = append(nodes, id[:]...)
	}
	return map[string]any{
		"name":       name,
		"set_size":   n,
		"nodes":      hex.EncodeToString(nodes),
		"pubkeys":    hex.EncodeToString(pks),
		"wire":       hex.EncodeToString(wire),
		"expect":     verdict(c.Verify(registryFor(n), 0)),
		"vote_count": len(c.Votes),
	}
}

func certVerify() []map[string]any {
	rows := make([]map[string]any, 0, 16)

	// The accepting rows, at the committee sizes the benchmarks report.
	for _, n := range []int{1, 4, 21, 41} {
		c := signedCert(n, uint32(n), chain.Quasar)
		rows = append(rows, verifyRow(fmt.Sprintf("verify/ok_%d", n), c, n, marshal(c)))
	}
	// Nova is the other rung a certificate may claim.
	{
		c := signedCert(4, 3, chain.Nova)
		rows = append(rows, verifyRow("verify/ok_nova", c, 4, marshal(c)))
	}

	// One row per refusal. Each mutates exactly one thing about an otherwise
	// valid certificate, so the row names the clause it trips.
	refusal := func(name string, mutate func(*chain.QuorumCert)) {
		c := signedCert(4, 3, chain.Quasar)
		mutate(c)
		rows = append(rows, verifyRow(name, c, 4, marshal(c)))
	}
	refusal("refuse/version", func(c *chain.QuorumCert) { c.Version = chain.QuorumCertVersion + 1 })
	refusal("refuse/role", func(c *chain.QuorumCert) { c.Type = chain.QCType(0x7F) })
	refusal("refuse/tier_photon", func(c *chain.QuorumCert) { c.Tier = chain.Photon })
	refusal("refuse/tier_horizon", func(c *chain.QuorumCert) { c.Tier = chain.Horizon })
	refusal("refuse/threshold_zero", func(c *chain.QuorumCert) { c.Threshold = 0 })
	refusal("refuse/no_votes", func(c *chain.QuorumCert) { c.Votes = nil })
	refusal("refuse/duplicate_voter", func(c *chain.QuorumCert) { c.Votes[2] = c.Votes[1] })
	refusal("refuse/unsorted", func(c *chain.QuorumCert) { c.Votes[0], c.Votes[1] = c.Votes[1], c.Votes[0] })
	refusal("refuse/not_accept", func(c *chain.QuorumCert) { c.Votes[1].Accept = false })
	refusal("refuse/flipped_signature_byte", func(c *chain.QuorumCert) { c.Votes[2].Signature[0] ^= 0x01 })
	refusal("refuse/signature_of_another_vote", func(c *chain.QuorumCert) {
		c.Votes[3].Signature = append([]byte(nil), c.Votes[0].Signature...)
	})
	refusal("refuse/below_threshold", func(c *chain.QuorumCert) { c.Threshold = 5 })
	refusal("refuse/unknown_voter", func(c *chain.QuorumCert) {
		var far ids.NodeID
		for i := range far {
			far[i] = 0xEE
		}
		c.Votes[3].NodeID = far
	})
	// A signature over a DIFFERENT position: the message Verify derives comes
	// from the certificate's own position, so lifting a valid vote from one
	// height to another cannot certify the second.
	refusal("refuse/vote_from_another_height", func(c *chain.QuorumCert) {
		other := certPosition()
		other.Height++
		c.Votes[1].Signature = bls.SignatureToBytes(bls.Sign(certKey(1), chain.CanonicalVoteMessage(other)))
	})
	// An empty signature field is well-formed on the wire and is not a
	// signature. The predicate that this corpus replaced accepted it.
	refusal("refuse/empty_signature", func(c *chain.QuorumCert) { c.Votes[0].Signature = nil })
	return rows
}
