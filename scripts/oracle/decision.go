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
//
// signer_floor is the RUNG's, not Nova's. Both rungs carry one — Nova's saturates
// at three and Quasar's is the export supermajority in seats — so a column that
// always reported Nova's would be telling the C++ gate the wrong number about the
// clause a Quasar row can now fail.
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
		// ONLY THE SEATS THAT CAN SIGN are projected. A C++ validator IS a public
		// key — QuorumCertEngine keys its set by one — so a member the chain
		// carries without a key is not a thing that implementation can represent,
		// and handing it one would be asking it to model a seat it has no slot
		// for. The projection is faithful precisely because it drops them: the set
		// C++ receives is the set every floor is read against in all three
		// implementations, and `total` below is its stake.
		//
		// What the chain carries is recorded beside it rather than lost, so the
		// keyless case still states its own point — that the denominator is the
		// smaller of the two numbers, and deliberately.
		var nodes, weights, signers []byte
		var carried, keyless uint64
		var n int
		for _, s := range c.Set {
			w := decimal(s.Weight)
			carried += w
			if s.Keyless {
				keyless += w
				continue
			}
			n++
			nodes = append(nodes, unhexed(s.NodeID)...)
			weights = binary.BigEndian.AppendUint64(weights, w)
		}
		for _, id := range c.Signers {
			signers = append(signers, unhexed(id)...)
		}

		expect := "reject"
		if c.Accept {
			expect = "accept"
		}

		rows = append(rows, map[string]any{
			"name":         c.Name,
			"rung":         c.Rung,
			"epoch":        v.Epoch,
			"set_size":     n,
			"nodes":        hex.EncodeToString(nodes),
			"weights":      hex.EncodeToString(weights),
			"signers":      hex.EncodeToString(signers),
			"signer_count": len(c.Signers),
			"total":        c.Total,
			"carried":      strconv.FormatUint(carried, 10),
			"keyless":      strconv.FormatUint(keyless, 10),
			"voted":        c.Voted,
			"signer_floor": c.SignerFloor,
			"stake_floor":  c.StakeFloor,
			"expect":       expect,
			"refusal":      c.Refusal,
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
