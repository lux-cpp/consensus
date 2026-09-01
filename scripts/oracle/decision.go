// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

// decision.go — the weighted finality DECISION, projected onto the flat schema.
//
// The rest of this corpus states what Go emits. That is necessary and it is not
// sufficient: an implementation can reproduce every byte and still finalize on
// the wrong number of signers, because encoding and deciding are different
// questions. The failure this closes already happened here — a build carrying no
// weighted predicate at all passed a corpus that only ever asked it to encode.
//
// Nothing is recomputed in this file. conformance.Build() runs the live
// predicate (chain.QuorumCert.VerifyWeighted) and records what it decided; this
// is only the flattening of that section onto the array-of-flat-objects schema
// the C++ reader accepts. So the rows here and the Go golden cannot disagree
// about what was decided — one definition, two projections.
//
// Weights and node ids are concatenated fixed-width hex, the same idiom
// cert_verify.json uses for its sets: a weight is 8 bytes big-endian, a node id
// is 20. A weight near 2^64 must never pass through a double, and the reader
// keeps every value as literal text for exactly that reason.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/luxfi/consensus/conformance"
)

// decisions projects the corpus's finality verdicts.
func decisions() []map[string]any {
	v := conformance.Build().Verdict

	rows := make([]map[string]any, 0, len(v.Finality))
	for _, c := range v.Finality {
		var nodes, weights, signers []byte
		for _, s := range c.Set {
			nodes = append(nodes, unhexed(s.NodeID)...)
			weights = binary.BigEndian.AppendUint64(weights, decimal(s.Weight))
		}
		for _, id := range c.Signers {
			signers = append(signers, unhexed(id)...)
		}

		expect := "reject"
		if c.Accept {
			expect = "accept"
		}

		rows = append(rows, map[string]any{
			"name":              c.Name,
			"rung":              c.Rung,
			"epoch":             v.Epoch,
			"set_size":          len(c.Set),
			"nodes":             hex.EncodeToString(nodes),
			"weights":           hex.EncodeToString(weights),
			"signers":           hex.EncodeToString(signers),
			"signer_count":      len(c.Signers),
			"total":             c.Total,
			"voted":             c.Voted,
			"nova_signer_floor": c.SignerFloor,
			"stake_floor":       c.StakeFloor,
			"expect":            expect,
			"refusal":           c.Refusal,
		})
	}
	return rows
}

// unhexed decodes an identifier the corpus recorded. A corpus that cannot be
// read is a corpus that cannot be regenerated, so this fails loudly.
func unhexed(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("oracle: corpus identifier is not hex: " + s)
	}
	return b
}

// decimal parses a weight the corpus recorded as a decimal string.
func decimal(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic("oracle: corpus weight is not a uint64: " + s)
	}
	return v
}
