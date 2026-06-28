# consensus2 seed — the finality GATE (pure C++23)

The SEED of `luxfi/consensus2`: a real, leaderless **finality gate** that does what
the toy stub (`luxfi/consensus` `pkg/c`) cannot — genuine BLS verification,
per-validator dedup, and a stake-weighted >2/3 supermajority, fail-closed. Local
only; not yet a GitHub repo.

## The finality rule (one rule, one place)
A block FINALIZES iff **α distinct validators** each produced a correctly
BLS-signed ACCEPT vote over the same canonical position `(block_id, height, epoch)`
**AND** the summed stake of those distinct voters is a **strict** two-thirds
supermajority: `voted > floor(2/3·total_stake)`. Fail-closed: `total_stake==0`,
an unknown block, or `α==0`/empty set never finalize. There is **no** ForceAccept
/ `k==1` / count-only path anywhere.

Ported to match the Go reference `engine/chain/quorum_cert.go`
(`Verify` + `VerifyWeighted`); the 2/3 floor is byte-identical to Go
`config.TwoThirdsStakeFloor` (`total=3q+r ⇒ 2q + (r==2?1:0)`).

## Decomplected (three orthogonal concerns)
- **Rule** — `QuorumCertEngine::is_final` / `verify_cert` (pure logic).
- **Crypto** — `cevm::crypto::bls` (blst-backed IRTF BLS12-381, POP ciphersuite).
  Never reinvented; the engine only *calls* a proven library.
- **Message** — `canonical_vote_message()`: domain-separated
  (`"LUX/chain/vote/v1\0"` + version + qc_type + position + accept byte). A sig for
  one (block,height,epoch,accept) can never be replayed at another.

## Layout
```
include/lux/consensus2/quorum_cert_engine.hpp   API + the rule, documented
src/quorum_cert_engine.cpp                       implementation (NEW)
test/toy_stub_killer_test.cpp                    the acceptance gate (5 scenarios)
CMakeLists.txt                                   builds blst → bls_signature → consensus2 → test
```

## Reused vs new
- **Reused, unmodified** (from the `~/work/luxcpp` checkout, NOT vendored):
  - `crypto/bls/cpp/bls_signature.{hpp,cpp}` — `cevm::crypto::bls` keygen / sign /
    verify / aggregate_sigs / fast_aggregate_verify (the genuine crypto core).
  - `blst/` — BLS12-381 backend, built from source by CMake (`server.c` + `assembly.S`).
- **New (the seed):** `QuorumCertEngine` (vote collection, dedup-by-key, stake gate,
  cert assemble/verify) + the toy-stub-killer test.
- **Considered and rejected:** `lux::quasar::WitnessVerifier` (single group-key
  threshold — wrong model; we need distinct per-validator keys+stake) and the
  `quasar::gpu` host shim (its stake-aware aggregation lives in the GPU wave kernel,
  needs a 32-byte subject, different DST — not standalone-drivable on CPU). We
  reproduce its security invariant ("stake aggregates only for verified votes;
  unverified lanes never accept") in the CPU gate.

## Build + test (spark; clang 18, CMake 3.28, aarch64)
```
cmake -S . -B build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_ASM_COMPILER=clang -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure      # or: ./build/toy_stub_killer_test
```
If the luxcpp checkout is elsewhere: `-DLUXCPP_ROOT=/path/to/luxcpp`.

## The toy-stub-killer test (5 scenarios, real keys)
1. α=4 of 5 validators (stake 20 each, 80>66) → FINAL; aggregate cert re-verifies
   (and a tampered/voter-dropped cert is rejected).
2. one validator's vote replayed 5× → NOT final (dedup; stake counted once).
3. 3 distinct votes (<α) → NOT final.
4. skewed stake `[10,10,10,10,60]`, α=3: 3 low-stake voters reach the COUNT but
   only 30 stake → NOT final (the stake gate is independent of the count gate);
   adding the whale (90>66) → final.
5. forged sig / wrong-position sig / out-of-set key → rejected, never counted; a
   rejected bad sig does not poison the validator's later valid vote.

**Teeth (verified by mutation):** removing the stake gate makes scenario 4 fail;
removing the dedup guard makes scenario 3 fail. The test exits non-zero on any
failed assertion.

## Scope (honest)
This is the finality **GATE only**. OUT of scope for the seed (later phases): Snow
sampling / re-poll, equivocation slashing, the PQ legs (ML-DSA / Ringtail /
Corona / Pulsar / Magnetar), networking/gossip, persistence, and the full Go
position axes (chain_id / round / parent_id / validator-set-root). The rule above
does not change when those land.
