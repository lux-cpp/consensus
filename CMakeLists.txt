# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# consensus — the finality GATE, in pure C++23. Builds:
#   blst (static, from source)  →  bls_signature (the reused domain-free bodies)
#     →  consensus (the gate + the Lux consensus vote domain)  →  the tests
#     →  luxconsensus_quasar (+ _c, the cgo ABI) — the witness verifier, a
#        SIBLING of the gate on the same blst
#
# Reused, unmodified, from the luxcpp checkout (NOT vendored here):
#   ${LUXCPP_ROOT}/blst                 — blst BLS12-381 backend
#   ${LUXCPP_ROOT}/crypto/bls/cpp       — cevm::crypto::bls (eth2 POP ciphersuite).
#     consensus uses it ONLY for the operations with no hash-to-curve; the vote
#     domain is BLS_SIG_..._RO_NUL_ and lives in src/bls.cpp. See bls.hpp.

cmake_minimum_required(VERSION 3.20)
project(consensus_seed LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Sanitizers, scoped to consensus's OWN code (the gate + Node + tests) — NOT the
# reused blst/bls_signature, which is audited assembly crypto we keep unmodified
# and whose instrumentation is both forbidden by policy and pathologically slow.
# Usage:  -DCONSENSUS_SANITIZE=address,undefined   or   -DCONSENSUS_SANITIZE=thread
set(CONSENSUS_SANITIZE "" CACHE STRING "Sanitizer set for consensus code only (e.g. address,undefined | thread)")

# Locate the reused luxcpp assets. The default is the parent of THIS repo, which
# is the luxcpp root when the repo sits where it belongs. CURRENT_SOURCE_DIR, not
# SOURCE_DIR: added as a subdirectory, SOURCE_DIR is the outer project and the
# default would point at the wrong tree — masked today only because node2 sets
# LUXCPP_ROOT before adding us.
get_filename_component(_default_luxcpp "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(LUXCPP_ROOT "${_default_luxcpp}" CACHE PATH "Path to the luxcpp checkout root")
set(BLST_DIR "${LUXCPP_ROOT}/blst"           CACHE PATH "blst source tree")
set(BLS_DIR  "${LUXCPP_ROOT}/crypto/bls/cpp" CACHE PATH "cevm::crypto::bls source dir")

foreach(_p "${BLST_DIR}/bindings/blst.h" "${BLS_DIR}/bls_signature.cpp")
  if(NOT EXISTS "${_p}")
    message(FATAL_ERROR "consensus seed: required reused asset not found: ${_p}\n"
                        "set -DLUXCPP_ROOT=/path/to/luxcpp")
  endif()
endforeach()

# blst ISA selection. blst/build.sh adds -D__ADX__ when the host reports adx;
# without it assembly.S compiles the mulq path and every field multiplication —
# so every pairing — runs on the slower generic code. Measured on evo: 24% on a
# verification. BLST_ISA=portable keeps both paths and dispatches at runtime.
set(BLST_ISA "auto" CACHE STRING "blst ISA: auto | adx | portable | generic")
set(BLST_ISA_FLAGS "")
if(BLST_ISA STREQUAL "portable")
  set(BLST_ISA_FLAGS -D__BLST_PORTABLE__)
elseif(BLST_ISA STREQUAL "adx")
  set(BLST_ISA_FLAGS -D__ADX__)
elseif(BLST_ISA STREQUAL "auto")
  if(EXISTS /proc/cpuinfo)
    file(READ /proc/cpuinfo _cpuinfo)
    if(_cpuinfo MATCHES "[ \t]adx[ \t\n]")
      set(BLST_ISA_FLAGS -D__ADX__)
    endif()
  endif()
endif()

# ── blst (BLS12-381 backend) — unity build mirroring blst/build.sh ────────────
add_library(blst STATIC
  "${BLST_DIR}/src/server.c"
  "${BLST_DIR}/build/assembly.S")
target_compile_options(blst PRIVATE -O2 -fno-builtin ${BLST_ISA_FLAGS})
target_include_directories(blst PUBLIC "${BLST_DIR}/bindings")

# ── cevm::crypto::bls — the REUSED genuine BLS sign/verify/aggregate surface ───
add_library(bls_signature STATIC "${BLS_DIR}/bls_signature.cpp")
target_include_directories(bls_signature PUBLIC "${BLS_DIR}")
target_link_libraries(bls_signature PUBLIC blst)

# ── consensus — the NEW finality gate (the seed) ─────────────────────────────
add_library(consensus STATIC
  src/threshold.cpp src/bls.cpp src/cert.cpp src/quorum_cert_engine.cpp src/wave.cpp src/node.cpp)
target_include_directories(consensus PUBLIC include)
# bls_signature carries the reused domain-free bodies; blst carries the curve. The
# consensus vote domain (src/bls.cpp) needs blst's headers directly — see bls.hpp.
target_link_libraries(consensus PUBLIC bls_signature blst)
target_compile_options(consensus PRIVATE -Wall -Wextra -Wpedantic)

# ── quasar — the witness verifier and its cgo ABI ─────────────────────────────
# The C++ hot-path port of Go protocol/quasar: Verify + AggregateThresholdSignatures.
# A SIBLING of the gate, not a layer of it: no gate source calls lux::quasar, and
# linking them would fabricate a dependency neither one has. Same blst, same NUL
# DST as the vote domain; it rides the from-source blst target above, so this tree
# has exactly ONE blst.
add_library(luxconsensus_quasar STATIC src/quasar_verify.cpp src/quasar_witness.cpp)
target_include_directories(luxconsensus_quasar PUBLIC include)
target_link_libraries(luxconsensus_quasar PUBLIC blst)
target_compile_options(luxconsensus_quasar PRIVATE -Wall -Wextra)

# The extern "C" surface, built as its own shared object so cgo consumers load the
# four lux_quasar_* symbols and nothing else. The name is a PUBLISHED CONTRACT:
# lux-private/multichain-cpp find_library's luxconsensus_quasar and find_path's
# lux/quasar.h. Do not rename either.
add_library(luxconsensus_quasar_c SHARED src/quasar_ffi.cpp)
target_link_libraries(luxconsensus_quasar_c PRIVATE luxconsensus_quasar blst)
target_include_directories(luxconsensus_quasar_c PUBLIC include)
target_compile_options(luxconsensus_quasar_c PRIVATE -Wall -Wextra)
set_target_properties(luxconsensus_quasar_c PROPERTIES OUTPUT_NAME luxconsensus_quasar)

# The gate is consumed by add_subdirectory (node2) and is never installed; the
# quasar pair is the one surface an outside build links against, so it is the one
# thing with an install rule.
include(GNUInstallDirs)
install(TARGETS luxconsensus_quasar luxconsensus_quasar_c
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/lux/quasar.h include/lux/quasar.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lux)

# ── tests ─────────────────────────────────────────────────────────────────────
# ONE list of test names, ONE loop. A new test is one line here: its source is
# test/<name>_test.cpp, its target <name>_test, its ctest name <name>. The
# sanitizer block below reads the SAME list, so a test can never be instrumented
# in one place and forgotten in another.
enable_testing()

set(CONSENSUS_TESTS
  toy_stub_killer      # the acceptance gate: no toy stub survives it
  poll_driver
  engine_integration
  multi_node
  batch_verify_attack
  no_double_finalize   # agreement: no two conflicting blocks finalize at a height
  liveness
  out_of_turn          # the acceptance window
  tier                 # the two finality rungs: Nova (accept) and Quasar (export)
  conformance          # the Go corpus: message bytes, DST, floors, thresholds
  pop_conformance      # the node-bound proof of possession, byte-for-byte vs Go & Rust
  quasar_verify        # the witness verifier vs the Go fixtures, C++ AND C ABI
  quasar_witness)      # threshold-share aggregation on Go's (index || sig) wire form

# The ZAP vote transport rides zap-cpp-core, so it is gated on -DZAP_DIR; core
# consensus has no ZAP dependency.
if (ZAP_DIR)
  list(APPEND CONSENSUS_TESTS zap_vote_transport)
endif()

foreach(_t ${CONSENSUS_TESTS})
  add_executable(${_t}_test test/${_t}_test.cpp)
  target_link_libraries(${_t}_test PRIVATE consensus)
  target_compile_options(${_t}_test PRIVATE -Wall -Wextra)
  add_test(NAME ${_t} COMMAND ${_t}_test)
endforeach()

if (ZAP_DIR)
  target_include_directories(zap_vote_transport_test PRIVATE "${ZAP_DIR}")
endif()

# The quasar tests exercise the witness surface and its C ABI, so they link the
# quasar pair on top of the gate. Their fixtures resolve from __FILE__/../../testdata
# — the corpus at this repo's root — so they need no argument.
foreach(_t quasar_verify quasar_witness)
  target_link_libraries(${_t}_test PRIVATE luxconsensus_quasar luxconsensus_quasar_c)
endforeach()

# The conformance harness reads the Go-generated corpus. CONFORMANCE_DIR points at
# whichever checkout holds it; the vectors shipped here are the default.
set(CONFORMANCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vectors" CACHE PATH
    "Directory holding the Go-generated conformance corpus")
target_compile_definitions(conformance_test PRIVATE
    CONSENSUS_VECTORS="${CONFORMANCE_DIR}")
target_compile_definitions(pop_conformance_test PRIVATE
    CONSENSUS_VECTORS="${CONFORMANCE_DIR}")

# Apply the requested sanitizer to consensus's OWN targets only (blst/bls stay
# clean — see CONSENSUS_SANITIZE above). One place; every consensus target gets
# the same instrumentation, the reused crypto none.
if (CONSENSUS_SANITIZE)
    set(_san -fsanitize=${CONSENSUS_SANITIZE} -fno-omit-frame-pointer)
    set(_targets consensus luxconsensus_quasar luxconsensus_quasar_c)
    foreach(_t ${CONSENSUS_TESTS})
        list(APPEND _targets ${_t}_test)
    endforeach()
    foreach(_t ${_targets})
        target_compile_options(${_t} PRIVATE ${_san})
        target_link_options(${_t} PRIVATE ${_san})
    endforeach()
endif()

# ── bench_trilang — the C++ leg of the three-language CPU comparison ──────────
# Off by default: it needs google-benchmark, and a build that cannot find it
# should still produce the library and the tests. -DCONSENSUS_BENCH=ON to build.
option(CONSENSUS_BENCH "Build the three-language comparison benchmark" OFF)
if(CONSENSUS_BENCH)
  find_package(benchmark REQUIRED)
  add_executable(bench_trilang bench/bench_trilang.cpp)
  target_link_libraries(bench_trilang PRIVATE consensus benchmark::benchmark)
  target_compile_options(bench_trilang PRIVATE -O3 -Wall -Wextra)
endif()
