# consensus2 — the finality GATE (pure C++23)

`luxfi/consensus2`: a real, leaderless **finality gate** — genuine BLS12-381
verification, per-validator dedup, and stake-weighted tier floors, fail-closed.
Embedded by `luxfi/node2`.

**Go is the source of truth.** `luxfi/consensus` (`engine/chain`, `config`,
`protocol/wave`) runs on mainnet; this implementation CONFORMS to it. Where the
two disagree, this one is wrong.

## The finality rule (one rule, one place)

A block finalizes **at a tier** iff that tier's floor of DISTINCT validators each
produced a correctly BLS-signed ACCEPT vote over the same canonical position, AND
their summed stake **strictly exceeds** that tier's stake floor:

| tier | signers | stake | authorizes |
|---|---|---|---|
| **Nova** | ≥ `nova_signer_floor(n)` | > `floor(total/2)` | local execution (crash-safe, reorgable) |
| **Quasar** | ≥ α | > `floor(2·total/3)` | export — bridges, DEX settlement, cross-chain |

Fail-closed: zero total stake, an unknown block, an unknown tier, or an empty set
never finalize. There is **no** force-accept, no `k==1`, no count-only path.
A cert cannot forge its tier upward — the verifier re-derives both floors from the
live validator set instead of reading the cert's own claim, so a Nova set of votes
relabelled Quasar dies on the ⅔ clause. Mirrors Go `QuorumCert.VerifyWeighted`.

## Decomplected

- **Rule** — `QuorumCertEngine::meets_quorum` / `verify_cert`. Pure logic.
- **Thresholds** — `threshold.hpp`. The gate enforces the stake floors and the
  wave sizes its per-round threshold from the same ⅔ rule; a second definition on
  either side is how a count gate drifts from the stake predicate it tracks. Go
  keeps them in `config` for exactly that reason.
- **Crypto** — `lux::consensus2::bls`. blst-backed, and it knows exactly ONE
  domain: the Lux consensus vote domain.
- **Message** — `canonical_vote_message()`. Deterministic, fixed-width, 226 bytes,
  byte-identical to Go `chain.CanonicalVoteMessage`.
- **Liveness** — `wave` (+ `photon` sampling). Carries no cryptographic weight.

### The domain tag is not a detail

A BLS signature is a hash-to-curve under a domain separation tag. Go signs
consensus votes under the **basic** ciphersuite

```
BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_       (luxfi/crypto bls.dstSignature)
```

The reused `cevm::crypto::bls` is the **eth2 precompile** ciphersuite and is
hard-wired to `..._RO_POP_` — correct for its domain, wrong for a consensus vote.
Same key, same message, different signature, and the two reject each other. So
`lux::consensus2::bls` is the one surface consensus2 signs through: the
domain-BOUND operations (`sign`, `verify`, `fast_aggregate_verify`) hash under
`kVoteDST` against blst; the domain-FREE ones (`keygen`, `sk_to_pk`,
`aggregate_sigs` — point arithmetic, no hash-to-curve) forward to the reused
bodies unchanged.

Aggregation over a common message is sound under the basic ciphersuite only when
every admitted pubkey has had a proof-of-possession verified upstream (P-chain
admission). The gate trusts the admitted set, as the Go engine does.

### The signed message

```
"LUX/chain/vote/v2\0"  version:2  qc_type:1
chain_id:32  height:8  round:4
canonical_block_id:32  parent_canonical_id:32
execution_state_root:32  payload_root:32  validator_set_root:32
accept:1                                             = 226 bytes
```

The **canonical/transport split** is the point. `{block_id, parent_id}` are the
outer proposervm envelope ids — transport cache keys, deliberately NOT signed. The
signed identity is the inner execution commitment, so two envelopes wrapping the
same inner block produce identical messages: their votes interoperate and their
certs are duplicate aliases, never a fork. A position that leaves the canonical
axes empty degrades to canonical == transport, resolved in ONE place
(`canonical_id_of`) so every producer signs the same bytes.

The per-height equivocation slot keys on the CANONICAL id for the same reason.
Height-only, never `(height, epoch)`: an epoch derives from a proposer-chosen
P-chain height, so keying on it fragments the slot and lets an honest validator
commit two siblings. Go keys `SlotKey{Height}`.

## Verification runs at the GATE

Votes join a block's tally as CANDIDATES with no per-vote pairing. The whole tally
is verified in ONE aggregate pairing when `is_final` / `assemble_cert` is asked,
at the tier asked — so a node pays one pairing per block for the rung it actually
consumes, and the engine never guesses which rung that is. `VoteResult::Recorded`
says exactly that and no more. If the aggregate fails, a forged sig is present:
individual verifies evict it and refund its stake, after which every survivor is
verified and the block's later votes each pay their own pairing.

`Node::poll` names a block by **id**, and reads the position back from the gate.
A caller cannot hand it a foreign position — which used to make the node sign a
vote its own gate would evict AND burn the wrong equivocation slot.

## Layout

```
include/lux/consensus2/threshold.hpp   the quorum floors — one home, two consumers
include/lux/consensus2/bls.hpp         the Lux consensus vote domain over blst
include/lux/consensus2/quorum_cert_engine.hpp   the gate: rule, position, cert
include/lux/consensus2/wave.hpp        FPC threshold voting + β confidence
include/lux/consensus2/photon.hpp      committee sampling (header-only)
include/lux/consensus2/node.hpp        one validator: poll, sign, disseminate
include/lux/consensus2/zap/            votes over the ZAP wire codec
src/                                   the bodies
test/                                  one file per name in CONSENSUS2_TESTS
```

## Reused vs new

- **Reused, unmodified** (from the `~/work/luxcpp` checkout, NOT vendored):
  `blst/` (built from source: `server.c` + `assembly.S`) and
  `crypto/bls/cpp/bls_signature.{hpp,cpp}` for the domain-free operations.
- **New:** everything under `include/lux/consensus2` and `src/`.

## Build + test

```
cmake -S . -B build -DLUXCPP_ROOT=/path/to/luxcpp \
      -DZAP_DIR=/path/to/zap-cpp-core/include -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Sanitizers cover consensus2's own code only (the reused assembly crypto stays
uninstrumented): `-DCONSENSUS2_SANITIZE=address,undefined` or `=thread`.

Tests live in ONE list in `CMakeLists.txt` (`CONSENSUS2_TESTS`). A new test is one
line there: source `test/<name>_test.cpp`, target `<name>_test`, ctest name
`<name>`. The sanitizer block reads the same list, so a test can never be
instrumented in one place and forgotten in another.

## What is NOT here

Honest scope. The gate, the wave, the sampler and a vote mesh — not the whole
engine. Missing, and known missing:

- **The PQ legs.** No ML-DSA / SLH-DSA / Ringtail. Go `protocol/quasar` is 15k
  lines of them.
- **A StakeSource.** The validator set is frozen at engine construction; Go reads
  stake and pubkeys at the block's P-chain epoch height.
- **The sampling round-trip.** `photon` samples and `wave` tallies, but no
  query/chit exchange runs on the wire; the embedder drives the tally.
- **Cert identity.** The cert keys voters by 48-byte BLS pubkey; Go keys by
  20-byte `ids.NodeID` and carries per-voter records with no aggregate field. The
  two cert shapes do not yet interchange.
- **The mesh transport.** Votes ride `zap-cpp-core` (the plugin-IPC codec), not
  the PQ-handshake AEAD session protocol the Go validator mesh speaks.
