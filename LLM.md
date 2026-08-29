# consensus — the finality GATE (pure C++23)

`luxcpp/consensus`: a real, leaderless **finality gate** — genuine BLS12-381
verification, per-validator dedup, and stake-weighted tier floors, fail-closed.
Embedded by `luxfi/node2`. Also carries the **Quasar witness** surface — the C++
hot-path port of Go `protocol/quasar` with the `lux_quasar_*` cgo ABI.

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
- **Crypto** — `lux::consensus::bls`. blst-backed, and it knows exactly ONE
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
`lux::consensus::bls` is the one surface consensus signs through: the
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
include/lux/consensus/threshold.hpp   the quorum floors — one home, two consumers
include/lux/consensus/bls.hpp         the Lux consensus vote domain over blst
include/lux/consensus/quorum_cert_engine.hpp   the gate: rule, position, cert
include/lux/consensus/wave.hpp        FPC threshold voting + β confidence
include/lux/consensus/photon.hpp      committee sampling (header-only)
include/lux/consensus/node.hpp        one validator: poll, sign, disseminate
include/lux/consensus/zap/            votes over the ZAP wire codec
include/lux/quasar.h                  the witness cgo ABI — a published contract
include/lux/quasar.hpp                WitnessVerifier / WitnessAggregator
src/                                   the bodies
test/                                  one file per name in CONSENSUS_TESTS
testdata/                              the Go witness fixtures (5, binary)
```

## Quasar witness — the sibling surface

The C++ hot-path port of Go `luxfi/consensus/protocol/quasar`: `Verify` +
`AggregateThresholdSignatures`, byte-stable with the Go side. It builds
`luxconsensus_quasar` (`WitnessVerifier` / `WitnessAggregator`, namespace
`lux::quasar`) plus `luxconsensus_quasar_c`, the extern-`"C"` shim exporting the
four `lux_quasar_*` symbols and nothing else.

A **sibling** of the gate, not a layer of it — no gate source calls `lux::quasar`.
Both ride the same from-source blst and the same `..._RO_NUL_` DST, so the tree
has exactly one blst and one signature domain, but neither library depends on the
other. The namespace stays `lux::quasar`: it does not collide with
`lux::consensus`, and renaming it would break the consumer below.

Deliberately **CPU-only** (`Backend::Gpu` is reserved behind the same enum):
per-round verify is latency-bound, and blst's assembly beats an unbatched CUDA
round trip. A future GPU backend swaps in behind the same C ABI without
recompiling any Go consumer.

Aggregation takes Go's threshold wire form — `shares_n` records of
`(index : u32 big-endian) || (sig : 96 bytes)`, mirroring
`luxfi/crypto/threshold/bls.SignatureShare`. That is a different shape from the
gate's `aggregate_sigs`, which takes a flat `96·n` concatenation with no index.

**Consumer:** `lux-private/multichain-cpp` links `luxconsensus_quasar` for real
CrossRef BLS verification (`lux_quasar_witness_verify`) and **fails closed** if
the library is unlinked. It locates the library by the name `luxconsensus_quasar`
and the header by the path `lux/quasar.h`. Neither may be renamed.

> The full Quasar engine (Photon→Wave→Focus; triple-seal BLS12-381 + Pulsar +
> ML-DSA-65) lives in Go `luxfi/consensus`.

## Reused vs new

- **Reused, unmodified** (from the `~/work/luxcpp` checkout, NOT vendored):
  `blst/` (built from source: `server.c` + `assembly.S`) and
  `crypto/bls/cpp/bls_signature.{hpp,cpp}` for the domain-free operations.
- **New:** everything under `include/lux/consensus` and `src/`.

## Build + test

```
cmake -S . -B build -DLUXCPP_ROOT=/path/to/luxcpp \
      -DZAP_DIR=/path/to/zap-cpp-core/include -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Sanitizers cover consensus's own code only (the reused assembly crypto stays
uninstrumented): `-DCONSENSUS_SANITIZE=address,undefined` or `=thread`.

TSan aborts with `FATAL: ThreadSanitizer: unexpected memory mapping` on kernels
that hand out 32 bits of mmap randomness — its shadow mapping does not fit. That
is the loader, not the code. Run the suite with randomization off:
`setarch -R ctest --test-dir build`. ASan needs no such thing.

Tests live in ONE list in `CMakeLists.txt` (`CONSENSUS_TESTS`). A new test is one
line there: source `test/<name>_test.cpp`, target `<name>_test`, ctest name
`<name>`. The sanitizer block reads the same list, so a test can never be
instrumented in one place and forgotten in another.

## The Go corpus

`scripts/oracle` READS the values out of the running Go implementation and writes
them to `vectors/`; `test/conformance_test.cpp` re-derives each one in C++ and
demands byte equality. Nothing in the harness states what the answer ought to be —
the corpus does, and the corpus is regenerable:

```
cd scripts/oracle && GOWORK=off go run . -out ../../vectors
```

Four files, four things pinned — exactly the four that had silently drifted:

| file | pins | from |
|---|---|---|
| `vote_message.json` | the 226-byte signed message, every axis, both decisions, the canonical degrade | `chain.CanonicalVoteMessage` |
| `vote_signature.json` | the domain tag, by pinning its output for real keys | `bls.Sign` |
| `stake_floor.json` | the ⅔ and ½ floors to `MaxUint64` | `config.TwoThirdsStakeFloor` / `HalfStakeFloor` |
| `committee.json` | `NovaQuorum`, `NovaSignerFloor`, `EqualStakeSupermajorityThreshold`, `AlphaForK` | `engine/chain`, `config` |

The signature rows also prove the trap directly: they sign the same key over the
same message through the reused eth2 POP surface and assert the result differs and
that the consensus domain rejects it.

Each file is a JSON **array of FLAT objects** whose values are strings, numbers or
booleans. That is the whole schema, deliberately the smallest thing a reader in
any language consumes without a dependency — the harness carries its own ~70-line
reader and rejects anything nested rather than skipping past it. Values are kept
as literal text so a `uint64` near `MaxUint64` never passes through a double.

`-DCONFORMANCE_DIR=` points the harness at another checkout's corpus; the vectors
here are the default. `luxfi/conformance` is the corpus's eventual home — promoting
these files there is a cross-repo change and has not been made.

`testdata/` is the second corpus, on the same discipline: five binary witness
fixtures the quasar tests read with no argument, regenerable from the same Go
source of truth. Bytes differ run to run only because the generator mints fresh
random keys; the sizes and the structure do not.

```
cd ~/work/lux/consensus && QUASAR_DUMP=<repo>/testdata \
  GOWORK=off go test -count=1 -run TestDumpWitnessFixtures ./protocol/quasar
```

Both regenerators reach the Go repos by RELATIVE path, so they are tied to where
this checkout sits. `scripts/oracle/go.mod` resolves `luxfi/consensus` and
`luxfi/crypto` as `../../../../lux/<repo>` — correct when this repo is at
`~/work/luxcpp/consensus`, beside the other `luxcpp` trees. Note the sibling trap:
`~/work/luxcpp/crypto` is the **C++** crypto, so a path that is merely short
resolves to the wrong repo rather than to nothing.

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
- **A C ABI for the gate.** Only the quasar witness surface exports one
  (`lux_quasar_*`). The gate is C++-only and is consumed by `add_subdirectory`;
  a cgo caller cannot reach `QuorumCertEngine` today.
