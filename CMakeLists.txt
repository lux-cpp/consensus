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
add_library(consensus2 STATIC src/quorum_cert_engine.cpp)
target_include_directories(consensus2 PUBLIC include)
target_link_libraries(consensus2 PUBLIC bls_signature)
target_compile_options(consensus2 PRIVATE -Wall -Wextra -Wpedantic)

# ── the acceptance gate: the toy-stub-killer test ─────────────────────────────
add_executable(toy_stub_killer_test test/toy_stub_killer_test.cpp)
target_link_libraries(toy_stub_killer_test PRIVATE consensus2)
target_compile_options(toy_stub_killer_test PRIVATE -Wall -Wextra)

enable_testing()
add_test(NAME toy_stub_killer COMMAND toy_stub_killer_test)
