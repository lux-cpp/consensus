# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# consensus2 seed — the finality GATE, in pure C++23. Builds:
#   blst (static, from source)  →  bls_signature (cevm::crypto::bls, REUSED)
#     →  consensus2 (the gate, NEW)  →  toy_stub_killer_test (the acceptance gate)
#
# Reused, unmodified, from the luxcpp checkout (NOT vendored here):
#   ${LUXCPP_ROOT}/blst                 — blst BLS12-381 backend
#   ${LUXCPP_ROOT}/crypto/bls/cpp       — cevm::crypto::bls IRTF signature surface

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
add_library(consensus2 STATIC src/quorum_cert_engine.cpp src/wave.cpp src/node.cpp)
target_include_directories(consensus2 PUBLIC include)
target_link_libraries(consensus2 PUBLIC bls_signature)
target_compile_options(consensus2 PRIVATE -Wall -Wextra -Wpedantic)

# ── the acceptance gate: the toy-stub-killer test ─────────────────────────────
add_executable(toy_stub_killer_test test/toy_stub_killer_test.cpp)
target_link_libraries(toy_stub_killer_test PRIVATE consensus2)
target_compile_options(toy_stub_killer_test PRIVATE -Wall -Wextra)

enable_testing()
add_test(NAME toy_stub_killer COMMAND toy_stub_killer_test)

add_executable(poll_driver_test test/poll_driver_test.cpp)
target_link_libraries(poll_driver_test PRIVATE consensus2)
target_compile_options(poll_driver_test PRIVATE -Wall -Wextra)
add_test(NAME poll_driver COMMAND poll_driver_test)

add_executable(engine_integration_test test/engine_integration_test.cpp)
target_link_libraries(engine_integration_test PRIVATE consensus2)
target_compile_options(engine_integration_test PRIVATE -Wall -Wextra)
add_test(NAME engine_integration COMMAND engine_integration_test)

add_executable(multi_node_test test/multi_node_test.cpp)
target_link_libraries(multi_node_test PRIVATE consensus2)
target_compile_options(multi_node_test PRIVATE -Wall -Wextra)
add_test(NAME multi_node COMMAND multi_node_test)

add_executable(batch_verify_attack_test test/batch_verify_attack_test.cpp)
target_link_libraries(batch_verify_attack_test PRIVATE consensus2)
target_compile_options(batch_verify_attack_test PRIVATE -Wall -Wextra)
add_test(NAME batch_verify_attack COMMAND batch_verify_attack_test)

# ── canonical-message parity KAT: the signed message is byte-for-byte the Go
#    reference (engine/chain/quorum_cert.go). A layout drift is a finality split.
add_executable(canonical_message_parity_test test/canonical_message_parity_test.cpp)
target_link_libraries(canonical_message_parity_test PRIVATE consensus2)
target_compile_options(canonical_message_parity_test PRIVATE -Wall -Wextra)
add_test(NAME canonical_message_parity COMMAND canonical_message_parity_test)

# ── BFT parity gap tests: agreement (no double finalize), liveness, acceptance window
add_executable(no_double_finalize_test test/no_double_finalize_test.cpp)
target_link_libraries(no_double_finalize_test PRIVATE consensus2)
target_compile_options(no_double_finalize_test PRIVATE -Wall -Wextra)
add_test(NAME no_double_finalize COMMAND no_double_finalize_test)

add_executable(liveness_test test/liveness_test.cpp)
target_link_libraries(liveness_test PRIVATE consensus2)
target_compile_options(liveness_test PRIVATE -Wall -Wextra)
add_test(NAME liveness COMMAND liveness_test)

add_executable(out_of_turn_test test/out_of_turn_test.cpp)
target_link_libraries(out_of_turn_test PRIVATE consensus2)
target_compile_options(out_of_turn_test PRIVATE -Wall -Wextra)
add_test(NAME out_of_turn COMMAND out_of_turn_test)

# ZAP vote transport — votes over the canonical ZAP wire codec (zap-cpp-core).
# Gated on -DZAP_DIR (the zap-cpp-core include root); core consensus2 has no ZAP dep.
if (ZAP_DIR)
    add_executable(zap_vote_transport_test test/zap_vote_transport_test.cpp)
    target_include_directories(zap_vote_transport_test PRIVATE "${ZAP_DIR}")
    target_link_libraries(zap_vote_transport_test PRIVATE consensus2)
    target_compile_options(zap_vote_transport_test PRIVATE -Wall -Wextra)
    add_test(NAME zap_vote_transport COMMAND zap_vote_transport_test)
endif()

# Apply the requested sanitizer to consensus2's OWN targets only (blst/bls stay
# clean — see CONSENSUS2_SANITIZE above). One place; every consensus2 target gets
# the same instrumentation, the reused crypto none.
if (CONSENSUS2_SANITIZE)
    set(_c2_san -fsanitize=${CONSENSUS2_SANITIZE} -fno-omit-frame-pointer)
    set(_c2_targets consensus2 toy_stub_killer_test poll_driver_test
        engine_integration_test multi_node_test batch_verify_attack_test
        canonical_message_parity_test
        no_double_finalize_test liveness_test out_of_turn_test)
    if (ZAP_DIR)
        list(APPEND _c2_targets zap_vote_transport_test)
    endif()
    foreach(_t ${_c2_targets})
        target_compile_options(${_t} PRIVATE ${_c2_san})
        target_link_options(${_t} PRIVATE ${_c2_san})
    endforeach()
endif()
