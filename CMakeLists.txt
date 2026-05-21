# Copyright (c) 2024-2026 Lux Industries Inc.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# Lux Consensus GPU Library - GPU-accelerated consensus operations
#
# Provides unified GPU acceleration for:
#   - Batch signature verification (BLS, ECDSA, Ed25519, ML-DSA)
#   - Merkle/Verkle tree operations
#   - Vote aggregation and threshold signatures
#
# Uses luxcpp/gpu as the backend abstraction layer.

cmake_minimum_required(VERSION 3.20)

project(lux-consensus-gpu
    VERSION 0.1.0
    DESCRIPTION "GPU-accelerated consensus operations"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# =============================================================================
# Options
# =============================================================================

option(LUX_CONSENSUS_BUILD_TESTS "Build tests" ON)
option(LUX_CONSENSUS_BUILD_BENCHMARKS "Build benchmarks" ON)

# =============================================================================
# Dependencies
# =============================================================================

# Core GPU library (luxcpp/gpu)
if(DEFINED LUX_GPU_DIR)
    set(LUX_GPU_INCLUDE ${LUX_GPU_DIR}/include)
elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/include/lux/gpu.h)
    set(LUX_GPU_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)
else()
    find_path(LUX_GPU_INCLUDE lux/gpu.h
        PATHS
            ${CMAKE_CURRENT_SOURCE_DIR}/../gpu/include
            /usr/local/include
            /usr/include
    )
endif()

if(NOT LUX_GPU_INCLUDE)
    message(FATAL_ERROR "Could not find lux/gpu.h")
endif()

message(STATUS "Using GPU headers from: ${LUX_GPU_INCLUDE}")

# Crypto library (luxcpp/crypto)
find_path(LUX_CRYPTO_INCLUDE lux/crypto.h
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/../crypto/include
        /usr/local/include
        /usr/include
)

# =============================================================================
# Library Sources
# =============================================================================

set(CONSENSUS_SOURCES
    src/batch_verify.cpp
    src/merkle_gpu.cpp
    src/vote_aggregation.cpp
    src/threshold_sign.cpp
)

# Imported from luxfi/consensus/pkg/cpp — ZeroMQ/MLX consensus harness.
# Different scope from luxconsensus_gpu (GPU kernels); built into a
# separate shared library so callers can opt into one or the other.
set(CONSENSUS_HARNESS_SOURCES
    src/chain.cpp
    src/consensus.cpp
    src/mlx_consensus.cpp
    src/network.cpp
    src/vote_processor.cpp
)

set(CONSENSUS_HEADERS
    include/lux/consensus/batch_verify.h
    include/lux/consensus/merkle_gpu.h
    include/lux/consensus/vote_aggregation.h
    include/lux/consensus/threshold_sign.h
    include/lux/consensus.h
)

# =============================================================================
# Consensus GPU Library
# =============================================================================

add_library(luxconsensus_gpu SHARED ${CONSENSUS_SOURCES})

target_include_directories(luxconsensus_gpu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${LUX_GPU_INCLUDE}
)

if(LUX_CRYPTO_INCLUDE)
    target_include_directories(luxconsensus_gpu PRIVATE ${LUX_CRYPTO_INCLUDE})
endif()

target_compile_definitions(luxconsensus_gpu PRIVATE
    LUX_CONSENSUS_GPU_BUILD
)

set_target_properties(luxconsensus_gpu PROPERTIES
    OUTPUT_NAME "luxconsensus_gpu"
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

# Platform suffix
if(APPLE)
    set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".dylib")
elseif(WIN32)
    set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".so")
endif()

# =============================================================================
# C API (for CGO bindings)
# =============================================================================

add_library(luxconsensus_gpu_c SHARED
    src/consensus_c_api.cpp
)

target_link_libraries(luxconsensus_gpu_c PRIVATE luxconsensus_gpu)

target_include_directories(luxconsensus_gpu_c PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# =============================================================================
# Installation
# =============================================================================

include(GNUInstallDirs)

install(TARGETS luxconsensus_gpu luxconsensus_gpu_c
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# =============================================================================
# Consensus Harness Library (imported from luxfi/consensus/pkg/cpp/)
# =============================================================================
#
# Builds only if all imported sources are present. Scope is the e2e test
# harness (ZeroMQ peer transport + MLX consensus); independent of the
# GPU kernel library above.

set(_harness_present TRUE)
foreach(_src ${CONSENSUS_HARNESS_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
        set(_harness_present FALSE)
        break()
    endif()
endforeach()

if(_harness_present)
    add_library(luxconsensus_harness STATIC ${CONSENSUS_HARNESS_SOURCES})
    target_include_directories(luxconsensus_harness PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    set_target_properties(luxconsensus_harness PROPERTIES
        OUTPUT_NAME "luxconsensus_harness"
        VERSION ${PROJECT_VERSION}
    )
    install(TARGETS luxconsensus_harness
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

install(DIRECTORY include/lux
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "=== Lux Consensus GPU Configuration ===")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  GPU Include: ${LUX_GPU_INCLUDE}")
message(STATUS "  Build Tests: ${LUX_CONSENSUS_BUILD_TESTS}")
message(STATUS "")
