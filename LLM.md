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

| tier | set | signers | stake | authorizes |
|---|---|---|---|---|
| **Nova** | n ≥ 1 | ≥ `nova_signer_floor(n)` | > `floor(total/2)` | local execution (crash-safe, reorgable) |
| **Quasar** | n ≥ `kMinBFTCommittee` (4) | ≥ `two_thirds_count(n)` | > `floor(2·total/3)` | export — bridges, DEX settlement, cross-chain |

The export rung carries a THIRD floor, `committee_floor`, and it is read against
the SET rather than against the votes. Byzantine tolerance is `f = (n-1)/3`, which
is zero for n of one, two and three: below four signers a two-thirds supermajority
tolerates no fault at all, so a unanimous certificate carrying every unit of stake
is forged by any single compromised key among its signers. Neither floor above
catches it, because both are read over n and both shrink with it —
`two_thirds_count(1)` is 1. Both entry points read it, `clears_floors` and
`verify_cert`, so a certificate cannot enter through the one that forgot. The
PORTABLE certificate (`cert.hpp`) now carries the same rule at
`Cert::verify_weighted(const Keys&, const Stake&)`: `Cert::verify` is the
structural and signature predicate and is NOT an accept rule, because its last
clause counts against the certificate's own threshold. Until it existed nothing on
this side could weigh a GOSSIPED certificate against a validator set, while Go's
gossip path could — a certificate two implementations admit and one cannot weigh is
not one rule. Both certificate types read one floor, the free function
`signer_floor(Tier, n)`, which is Go's `chain.SignerFloor` and Rust's
`finality::signer_floor`.

**A certificate states its quorum; it does not choose it.** Both verifiers require
`threshold == signer_floor(tier, n)` exactly — equality, not a lower bound, in both
directions. `vectors/decision.json` carries the declaration beside the derived floor
so the two can be checked against each other, and three of its eighteen rows declare
something else on purpose. The LOCAL gate (`is_final`) is handed no certificate and
therefore no declaration, so it accepts those three: two objects, two questions.
Nova
floors at one: it authorizes only local execution the chain can reorg away, and a
four-signer floor there would stop a small chain making any progress in exchange
for a guarantee the rung never offered. Go `engine/chain.minBFTCommittee`, Rust
`MIN_BFT_COMMITTEE`.

Both floors of both rungs are **derived from the live set**, never configured.
`QuorumCertEngine` takes the validator set and nothing else. The export count floor
used to be the `alpha` constructor parameter, which made the number of independent
parties export finality reports a value the operator picks — and at `alpha = 1` it
reports one, so a validator holding two thirds of the stake could mint an
export-grade certificate on a single signature. `two_thirds_count(n)` =
`floor(2n/3)+1` is the same supermajority the stake floor asks for, read in seats;
Go's `config.TwoThirdsCount` and Rust's `two_thirds_count` are the same number.
Neither half of a rung is sufficient alone.

`alpha` survives only as the WAVE's per-round sampling ratio (`alpha_threshold(k,
alpha)`, `kConsensusSuperMajority` = 0.69) — a different quantity that shares a
letter and nothing else.

Fail-closed: zero signer stake, an unknown block, an unknown tier, an empty set, a
signing set below the minimum Byzantine committee at the export rung, or an
unresolved validator count never finalize. There is **no** force-accept, no
`k==1`, no count-only path. A cert cannot forge its tier upward — the verifier
re-derives both floors from the live validator set instead of reading the cert's own
claim, so a Nova set of votes relabelled Quasar dies on the ⅔ clause. Mirrors Go
`QuorumCert.VerifyWeighted`.

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

`Party::poll` names a block by **id**, and reads the position back from the gate.
A caller cannot hand it a foreign position — which used to make the node sign a
vote its own gate would evict AND burn the wrong equivocation slot.

## Admission — the set the rule runs on

A certificate is only as sound as the set it is checked against, and until
`registration.hpp` there was no door: a caller built a `Registry` by calling
`insert()` with whatever pairs it liked, so ONE key holder could be seated under
MANY node ids. A two-signer floor was then cleared by one signature, and nothing
downstream could catch it — the verifier is right to accept a set that says two
nodes signed. `admit()` is the one door, and it enforces Go
`validator/registration.go` clause for clause, **in the order the code runs
them**:

```
KEY          a registration with no key at all cannot sign
ZERO WEIGHT  before the pairing — free, and refused whatever the proof says
             (Go checks r.Weight == 0 ahead of pop.Verify for the same reason)
ENCODING     canonical compressed G1 key, canonical compressed G2 proof
POSSESSION   bls::pop_verify — the proof binds THIS key to THIS node
UNIQUENESS   one key ↔ one node, on BOTH axes (neither implies the other)
WEIGHT       counted last — weight counted before uniqueness is counted twice
```

ENCODING and POSSESSION are one call. `bls::pop_verify` owns **one point, one
encoding** as part of its Key leg — the key must be the canonical spelling of the
point it decodes to — because that is where Go keeps it (`pop.Verify`), so the
next caller of the primitive inherits the rule instead of having to remember it.
blst refuses a non-canonical `x` on the way in, so the clause is a wall behind a
wall: 401,016 swept candidates, 101,541 of which decode, 0 non-canonical.

Possession alone is **not** enough, and that is the whole reason uniqueness is a
separate clause: the holder of a key can mint a genuine node-bound proof for any
identity it likes, so every registration in a many-nodes-one-key set is
individually sound. Only a rule over the SET refuses it.

The set is admitted **whole or not at all** — one bad registration fails the call
rather than being dropped, because a set that silently loses a signer has a total
weight that no longer describes it, and both stake floors are taken of that
total.

**The verdict and the admitted set are functions of the SET; the refusal REASON
is only for sets of distinct node ids.** The walk is a *stable* sort on the node
id, which is total exactly when the ids are distinct. Two registrations sharing a
node id it cannot separate, so their input order survives into the walk and can
decide which clause answers — one that stakes nothing and one whose proof was
minted elsewhere refuse as `zero_weight` or `possession` depending on which is
written first. Both orders refuse, and neither leaves a partial set. Go does the
same thing (`slices.SortStableFunc`), so this is parity, not drift: a tie-break
on the key would make the reason total at the cost of the parity, to buy a reason
nobody consumes. `test/registration_test.cpp` [6] pins both halves.

`CanonicalSet` is ordered ascending by the **compressed** key (never the
uncompressed form, which is 96 bytes under one crypto build and 48 under another
and orders the same set two ways). It is the one producer of a
`QuorumCertEngine`'s validators (`weights()`) and of a cert `Registry`
(`install()`, which refuses a non-empty registry so a retired set cannot carry
over into a live one).

**`install()` is the ONE seating route, and the seat holds the rule itself.**
`Registry::insert` is private with `CanonicalSet` its only friend, so there is no
hand to build a registry with; and because `CanonicalSet` is a plain aggregate
that anyone can write down without going through `admit()`, `insert` refuses a
key already seated under another node and a node already seated (Go's
`ErrDuplicateKey` / `ErrDuplicateNode`). A forged set therefore seats **nothing**:
`install` builds beside the caller's registry and moves in only on full success,
so a midway refusal cannot leave a prefix resolving half a validator set. The
door and the seat both refuse the hazard, and the door is the only one that can
demand possession.

Anything that needs a `Registry` says so through a `CanonicalSet` — including
`conformance_test` (the Go corpus rows) and `bench_trilang`. A benchmark that
reached past the door would be timing a shape production cannot build.

**The validator identity is the 20-byte NodeID** — `lux::consensus::Node`, in
`cert.hpp`, the identity a certificate's votes carry and the same 20 bytes the
proof of possession binds. `registration.hpp` static-asserts it against
`bls::kNodeLen` so the wire's spelling of that width and the proof preimage's
cannot drift apart.

**The participant is a `Party`.** `lux::consensus::Node` (the 20-byte id,
`cert.hpp`) and the participant class in `node.hpp` were both `Node`, so no
translation unit could hold `cert.hpp` and `node.hpp` at once — and the admission
door, whose whole vocabulary is that identity, could not be wired to the thing
that runs consensus. The id keeps the name it has in Rust (`Node`) and Go
(`ids.NodeID`); the participant is `Party`, the standard word for one.
`test/party_test.cpp` holds both headers and takes registrations through
`admit()` to a live mesh and a verified certificate.

> **The FILE stays `node.hpp`.** `lux-cpp/node` and `lux-cpp/sdk` locate this
> checkout by `find_checkout(... "include/lux/consensus/node.hpp" ...)`. Renaming
> the type is a rename; renaming the path is a break. Those two repos DO name
> `consensus::Node` (`node_host.hpp`/`.cpp`, `sdk/chain.hpp`,
> `sdk/example/chain.cpp`, `node/test/*`) and must be updated to `Party` when this
> lands.

## Layout

```
include/lux/consensus/threshold.hpp   the quorum floors — one home, two consumers
include/lux/consensus/bls.hpp         the Lux consensus vote domain over blst
include/lux/consensus/quorum_cert_engine.hpp   the gate: rule, position, cert
include/lux/consensus/registration.hpp the admission door: proof, uniqueness, weight
include/lux/consensus/wave.hpp        FPC threshold voting + β confidence
include/lux/consensus/photon.hpp      committee sampling (header-only)
include/lux/consensus/node.hpp        Party — one participant: poll, sign, send
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
`<name>`. The sanitizer and coverage blocks read the same list through
`CONSENSUS_OWN_TARGETS`, so a test can never be instrumented in one place and
forgotten in another.

## Coverage

```
cmake -S . -B build-cov -DLUXCPP_ROOT=/path/to/luxcpp -DCMAKE_BUILD_TYPE=Debug \
      -DCONSENSUS_COVERAGE=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build-cov --target coverage        # the report
cmake --build build-cov --target coverage-show   # the same profile, per line, as HTML
```

Clang's source-based coverage, and a build with any other compiler says so rather
than measuring nothing. Two reasons for it over gcov. It counts REGIONS, so a line
carrying two clauses reports both and a half-tested predicate cannot read as
covered — the only measure worth quoting about a gate whose clauses ARE the rule.
And it is the same instrumentation `cargo llvm-cov` reports the Rust crate with,
so the C++ number and the Rust number mean one thing.

Scoped like the sanitizers: blst and bls_signature stay clean. The report is read
from the test binaries and filtered back to `src/` and `include/`, because
llvm-cov cannot open a static archive and an archive's members alone lose the
header inline functions. llvm-cov warns that some functions have mismatched data —
the per-test `main`s, one per binary under one name; they are in `test/`, which
the filter drops.

The gate stands at 99.08% of regions and 100% of functions. The remaining eight
are defensive arms behind walls that already hold: a pairing failure over points
both callers decoded, aggregation over signatures each already verified, a
canonical round trip blst refuses on the way in, an uncompress after `pop_verify`
decoded the same bytes, `total_stake_ == 0` after a constructor that refuses an
empty set and every zero-stake member, and two `return "unknown"` arms after
switches covering every enumerator. Go and Rust carry the same walls in the same
places and their coverage stops at the same lines.

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
  stake and pubkeys at the block's P-chain epoch height. Note what is NOT missing:
  a `Validator` here IS a public key and the engine's set is keyed by one, so a
  member the chain carries without a key has no slot to occupy and `total_stake_`
  is the SIGNER stake.

  It is the signer stake by ENFORCEMENT, not by construction, and the difference
  mattered. A `PubKey` is a `std::array<uint8_t,48>`, so it is always PRESENT and
  presence proves nothing: forty-eight zero bytes are a well-formed value and not a
  point of G1. Such a seat held stake in every denominator and could never produce
  a signature this engine accepts — the spectator this implementation was said to
  have no slot for, admitted through the front door and stranding the export rung
  exactly as a keyless member does in Go and Rust, silently, because nothing here
  decoded the key until a vote arrived that never came. The constructor now runs
  `bls::key_validate` on every seat — canonical compressed G1, in the prime-order
  subgroup, not the identity, one point one encoding — which is the SAME function
  `pop_verify`'s Key leg is, so the door and the proof cannot come to disagree
  about what a key is. A dead key is a construction error.

  `conformance_test` conforms the denominator directly: each row states what the
  chain carries and what its signers hold, in stake (`carried`/`total`) and in
  seats (`roll`/`set_size`), and checks this engine reached the smaller of each.
  A keyless row is only worth having if the roll reading would have refused it, so
  the harness checks that too — in either unit, since `quasar_keyless_stake` is
  stranded in stake and `quasar_keyless_count` in seats.
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
