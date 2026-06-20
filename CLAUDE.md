# luxcpp/consensus — Quasar BLS verifier (C++ hot path)

Part of the Lux stack. **Architecture → [`../../LUX-STACK-MAP.md`](../../LUX-STACK-MAP.md)** (Layer 3 — consensus); the top-level `~/work/CLAUDE.md` auto-loads as the index.

**Role:** the C++ hot-path port of the Go `luxfi/consensus` **Quasar** engine — `Verify` + `AggregateThresholdSignatures`, byte-stable parity with the Go side. Builds `libluxconsensus_quasar` (`WitnessVerifier` / `WitnessAggregator`) + an extern-"C" cgo shim (`lux_quasar_*`). IRTF BLS12-381 (G1 pubkey 48 B / G2 sig 96 B, hash-to-G2 via SSWU / RFC 9380), backed by **blst** (static). Deliberately **CPU-only** (`Backend::Gpu` reserved) — per-round verify is latency-bound and blst asm beats unbatched CUDA.

> The full Quasar engine (Photon→Wave→Focus; triple-seal **BLS12-381 + Pulsar + ML-DSA-65**) lives in Go `luxfi/consensus`. The "Quasar wave scheduler" GPU kernel template is in `lux-private/gpu-kernels/kernels/cevm/quasar/`.

**Key files:** `include/lux/quasar.hpp`. Consumed by `lux-private/multichain-cpp` for real CrossRef BLS verification (`lux_quasar_witness_verify`, fails closed if unlinked).
