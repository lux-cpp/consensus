# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# consensus2 — the finality GATE, in pure C++23. Builds:
#   blst (static, from source)  →  bls_signature (the reused domain-free bodies)
#     →  consensus2 (the gate + the Lux consensus vote domain)  →  the tests
#
# Reused, unmodified, from the luxcpp checkout (NOT vendored here):
#   ${LUXCPP_ROOT}/blst                 — blst BLS12-381 backend
#   ${LUXCPP_ROOT}/crypto/bls/cpp       — cevm::crypto::bls (eth2 POP ciphersuite).
#     consensus2 uses it ONLY for the operations with no hash-to-curve; the vote
#     domain is BLS_SIG_..._RO_NUL_ and lives in src/bls.cpp. See bls.hpp.

cmake_minimum_required(VERSION 3.20)
project(consensus2_seed LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Sanitizers, scoped to consensus2's OWN code (the gate + Node + tests) — NOT the
# reused blst/bls_signature, which is audited assembly crypto we keep unmodified
# and whose instrumentation is both forbidden by policy and pathologically slow.
# Usage:  -DCONSENSUS2_SANITIZE=address,undefined   or   -DCONSENSUS2_SANITIZE=thread
set(CONSENSUS2_SANITIZE "" CACHE STRING "Sanitizer set for consensus2 code only (e.g. address,undefined | thread)")

# Locate the reused luxcpp assets (default: the parent of this seed dir).
get_filename_component(_default_luxcpp "${CMAKE_SOURCE_DIR}/.." ABSOLUTE)
set(LUXCPP_ROOT "${_default_luxcpp}" CACHE PATH "Path to the luxcpp checkout root")
set(BLST_DIR "${LUXCPP_ROOT}/blst"           CACHE PATH "blst source tree")
set(BLS_DIR  "${LUXCPP_ROOT}/crypto/bls/cpp" CACHE PATH "cevm::crypto::bls source dir")

foreach(_p "${BLST_DIR}/bindings/blst.h" "${BLS_DIR}/bls_signature.cpp")
  if(NOT EXISTS "${_p}")
    message(FATAL_ERROR "consensus2 seed: required reused asset not found: ${_p}\n"
                        "set -DLUXCPP_ROOT=/path/to/luxcpp")
  endif()
endforeach()

# ── blst (BLS12-381 backend) — unity build mirroring blst/build.sh ────────────
add_library(blst STATIC
  "${BLST_DIR}/src/server.c"
  "${BLST_DIR}/build/assembly.S")
target_compile_options(blst PRIVATE -O2 -fno-builtin)
target_include_directories(blst PUBLIC "${BLST_DIR}/bindings")

# ── cevm::crypto::bls — the REUSED genuine BLS sign/verify/aggregate surface ───
add_library(bls_signature STATIC "${BLS_DIR}/bls_signature.cpp")
target_include_directories(bls_signature PUBLIC "${BLS_DIR}")
target_link_libraries(bls_signature PUBLIC blst)

# ── consensus2 — the NEW finality gate (the seed) ─────────────────────────────
add_library(consensus2 STATIC
  src/threshold.cpp src/bls.cpp src/quorum_cert_engine.cpp src/wave.cpp src/node.cpp)
target_include_directories(consensus2 PUBLIC include)
# bls_signature carries the reused domain-free bodies; blst carries the curve. The
# consensus vote domain (src/bls.cpp) needs blst's headers directly — see bls.hpp.
target_link_libraries(consensus2 PUBLIC bls_signature blst)
target_compile_options(consensus2 PRIVATE -Wall -Wextra -Wpedantic)

# ── tests ─────────────────────────────────────────────────────────────────────
# ONE list of test names, ONE loop. A new test is one line here: its source is
# test/<name>_test.cpp, its target <name>_test, its ctest name <name>. The
# sanitizer block below reads the SAME list, so a test can never be instrumented
# in one place and forgotten in another.
enable_testing()

set(CONSENSUS2_TESTS
  toy_stub_killer      # the acceptance gate: no toy stub survives it
  poll_driver
  engine_integration
  multi_node
  batch_verify_attack
  no_double_finalize   # agreement: no two conflicting blocks finalize at a height
  liveness
  out_of_turn          # the acceptance window
  tier                 # the two finality rungs: Nova (accept) and Quasar (export)
  conformance)         # the Go corpus: message bytes, DST, floors, thresholds

# The ZAP vote transport rides zap-cpp-core, so it is gated on -DZAP_DIR; core
# consensus2 has no ZAP dependency.
if (ZAP_DIR)
  list(APPEND CONSENSUS2_TESTS zap_vote_transport)
endif()

foreach(_t ${CONSENSUS2_TESTS})
  add_executable(${_t}_test test/${_t}_test.cpp)
  target_link_libraries(${_t}_test PRIVATE consensus2)
  target_compile_options(${_t}_test PRIVATE -Wall -Wextra)
  add_test(NAME ${_t} COMMAND ${_t}_test)
endforeach()

if (ZAP_DIR)
  target_include_directories(zap_vote_transport_test PRIVATE "${ZAP_DIR}")
endif()

# The conformance harness reads the Go-generated corpus. CONFORMANCE_DIR points at
# whichever checkout holds it; the vectors shipped here are the default.
set(CONFORMANCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vectors" CACHE PATH
    "Directory holding the Go-generated conformance corpus")
target_compile_definitions(conformance_test PRIVATE
    CONSENSUS2_VECTORS="${CONFORMANCE_DIR}")

# Apply the requested sanitizer to consensus2's OWN targets only (blst/bls stay
# clean — see CONSENSUS2_SANITIZE above). One place; every consensus2 target gets
# the same instrumentation, the reused crypto none.
if (CONSENSUS2_SANITIZE)
    set(_c2_san -fsanitize=${CONSENSUS2_SANITIZE} -fno-omit-frame-pointer)
    set(_c2_targets consensus2)
    foreach(_t ${CONSENSUS2_TESTS})
        list(APPEND _c2_targets ${_t}_test)
    endforeach()
    foreach(_t ${_c2_targets})
        target_compile_options(${_t} PRIVATE ${_c2_san})
        target_link_options(${_t} PRIVATE ${_c2_san})
    endforeach()
endif()
