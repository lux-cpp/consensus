# Copyright (c) 2024-2026 Lux Industries Inc.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# Lux Consensus C++ — quasar witness verifier + GPU consensus ops.
#
# Quasar (always built, requires blst):
#   - luxconsensus_quasar       : C++ surface (WitnessVerifier, WitnessAggregator)
#   - luxconsensus_quasar_c     : extern "C" ABI for cgo (lux_quasar_*)
#
# GPU consensus ops (optional, requires lux/gpu.h):
#   - luxconsensus_gpu          : GPU acceleration for batch verify / merkle / votes
#
# ZMQ test harness (opt-in via LUX_CONSENSUS_BUILD_ZMQ_HARNESS):
#   - luxconsensus_harness      : E2E test scaffold (NOT production transport)

cmake_minimum_required(VERSION 3.20)

project(lux-consensus
    VERSION 0.2.0
    DESCRIPTION "Lux consensus C++ — quasar witness + GPU ops"
    LANGUAGES CXX
)

# C++20 is required by the quasar surface (std::span). The pre-existing
# GPU/ZMQ harness still compiles at C++17/20 individually (per-target).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(GNUInstallDirs)

# =============================================================================
# Options
# =============================================================================

option(LUX_CONSENSUS_BUILD_TESTS "Build tests" ON)
option(LUX_CONSENSUS_BUILD_BENCHMARKS "Build benchmarks" ON)
option(LUX_CONSENSUS_BUILD_QUASAR "Build quasar witness verifier" ON)

if(LUX_CONSENSUS_BUILD_TESTS)
    enable_testing()
endif()

# =============================================================================
# Dependencies
# =============================================================================

# Core GPU library (luxcpp/gpu) — OPTIONAL. Only required by the
# luxconsensus_gpu target. The quasar verifier path stays GPU-free.
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

if(LUX_GPU_INCLUDE)
    message(STATUS "lux/gpu.h: ${LUX_GPU_INCLUDE} (GPU ops enabled)")
else()
    message(STATUS "lux/gpu.h: NOT FOUND (GPU ops disabled, quasar still builds)")
endif()

# blst — required by quasar. Look for the .a in any of the cevm/crypto
# build trees that already produce it, or the env-supplied LUX_BLST_DIR.
if(LUX_CONSENSUS_BUILD_QUASAR)
    if(DEFINED ENV{LUX_BLST_DIR})
        set(LUX_BLST_DIR $ENV{LUX_BLST_DIR})
    elseif(NOT DEFINED LUX_BLST_DIR)
        # Probe the standard locations cevm + crypto build under.
        foreach(_p
            "${CMAKE_CURRENT_SOURCE_DIR}/../cevm/build/deps/src/blst"
            "${CMAKE_CURRENT_SOURCE_DIR}/../cevm/build-cpu-only/blst-oracle/src/blst_oracle"
            "${CMAKE_CURRENT_SOURCE_DIR}/../crypto/build/blst-oracle/src/blst_oracle"
            "${CMAKE_CURRENT_SOURCE_DIR}/../blst"
        )
            if(EXISTS "${_p}/libblst.a")
                set(LUX_BLST_DIR "${_p}")
                break()
            endif()
        endforeach()
    endif()
    if(NOT LUX_BLST_DIR OR NOT EXISTS "${LUX_BLST_DIR}/libblst.a")
        message(FATAL_ERROR
            "quasar build needs libblst.a. Searched standard build trees. "
            "Set -DLUX_BLST_DIR=/path/to/blst or LUX_BLST_DIR env var. "
            "Disable quasar with -DLUX_CONSENSUS_BUILD_QUASAR=OFF.")
    endif()
    # blst bindings/blst.h
    set(_BLST_INCLUDE "")
    foreach(_inc
        "${LUX_BLST_DIR}/bindings"
        "${CMAKE_CURRENT_SOURCE_DIR}/../blst/bindings"
    )
        if(EXISTS "${_inc}/blst.h")
            set(_BLST_INCLUDE "${_inc}")
            break()
        endif()
    endforeach()
    if(NOT _BLST_INCLUDE)
        message(FATAL_ERROR "blst.h not found near ${LUX_BLST_DIR}; clone blst into ../blst or set bindings include path")
    endif()
    set(LUX_BLST_INCLUDE "${_BLST_INCLUDE}")
    message(STATUS "blst static: ${LUX_BLST_DIR}/libblst.a")
    message(STATUS "blst header: ${LUX_BLST_INCLUDE}/blst.h")

    add_library(blst_imported STATIC IMPORTED)
    set_target_properties(blst_imported PROPERTIES
        IMPORTED_LOCATION "${LUX_BLST_DIR}/libblst.a"
        INTERFACE_INCLUDE_DIRECTORIES "${LUX_BLST_INCLUDE}")
endif()

# Crypto library (luxcpp/crypto) — OPTIONAL.
find_path(LUX_CRYPTO_INCLUDE lux/crypto.h
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/../crypto/include
        /usr/local/include
        /usr/include
)

# =============================================================================
# Quasar witness verifier — hot-path BLS verify + share aggregator
# =============================================================================
#
# Production-grade C++ implementation of luxfi/consensus/protocol/quasar
# Verify and AggregateThresholdSignatures. Binds to blst PRIVATE (so the
# consensus_quasar shared lib does not re-export blst symbols). The C ABI
# in include/lux/quasar.h is the cgo bridge contract.

if(LUX_CONSENSUS_BUILD_QUASAR)
    set(QUASAR_CXX_SOURCES
        src/quasar_verify.cpp
        src/quasar_witness.cpp
    )
    add_library(luxconsensus_quasar STATIC ${QUASAR_CXX_SOURCES})
    target_include_directories(luxconsensus_quasar
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )
    target_compile_features(luxconsensus_quasar PUBLIC cxx_std_20)
    target_compile_options(luxconsensus_quasar PRIVATE -O3 -Wall -Wextra)
    target_link_libraries(luxconsensus_quasar PRIVATE blst_imported)
    set_target_properties(luxconsensus_quasar PROPERTIES
        OUTPUT_NAME "luxconsensus_quasar"
        POSITION_INDEPENDENT_CODE ON)

    # C ABI shim for cgo. Builds the same C++ surface into a separate
    # shared library that exports only the extern "C" entry points.
    add_library(luxconsensus_quasar_c SHARED src/quasar_ffi.cpp)
    target_link_libraries(luxconsensus_quasar_c PRIVATE luxconsensus_quasar blst_imported)
    target_include_directories(luxconsensus_quasar_c PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_features(luxconsensus_quasar_c PRIVATE cxx_std_20)
    target_compile_options(luxconsensus_quasar_c PRIVATE -O3 -Wall -Wextra)
    set_target_properties(luxconsensus_quasar_c PROPERTIES
        OUTPUT_NAME "luxconsensus_quasar"
        VERSION ${PROJECT_VERSION}
        SOVERSION 0)
    if(APPLE)
        set_target_properties(luxconsensus_quasar_c PROPERTIES SUFFIX ".dylib")
    elseif(WIN32)
        set_target_properties(luxconsensus_quasar_c PROPERTIES SUFFIX ".dll")
    else()
        set_target_properties(luxconsensus_quasar_c PROPERTIES SUFFIX ".so")
    endif()

    install(TARGETS luxconsensus_quasar luxconsensus_quasar_c
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES
        include/lux/quasar.h
        include/lux/quasar.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lux)

    if(LUX_CONSENSUS_BUILD_TESTS)
        add_executable(test_quasar_verify tests/test_quasar_verify.cpp)
        target_link_libraries(test_quasar_verify PRIVATE luxconsensus_quasar luxconsensus_quasar_c blst_imported)
        target_compile_features(test_quasar_verify PRIVATE cxx_std_20)
        target_compile_options(test_quasar_verify PRIVATE -O3 -Wall -Wextra)
        add_test(NAME quasar_verify_parity
            COMMAND test_quasar_verify "${CMAKE_CURRENT_SOURCE_DIR}/testdata")
        set_tests_properties(quasar_verify_parity PROPERTIES TIMEOUT 60)

        add_executable(test_quasar_witness tests/test_quasar_witness.cpp)
        target_link_libraries(test_quasar_witness PRIVATE luxconsensus_quasar luxconsensus_quasar_c blst_imported)
        target_compile_features(test_quasar_witness PRIVATE cxx_std_20)
        target_compile_options(test_quasar_witness PRIVATE -O3 -Wall -Wextra)
        add_test(NAME quasar_witness_aggregate
            COMMAND test_quasar_witness "${CMAKE_CURRENT_SOURCE_DIR}/testdata")
        set_tests_properties(quasar_witness_aggregate PROPERTIES TIMEOUT 60)
    endif()
endif()

# =============================================================================
# Library Sources (GPU consensus ops — optional)
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
# Consensus GPU Library — builds only if planned source files exist
# AND lux/gpu.h is on disk (GPU backend is optional; quasar above does
# not need it).
# =============================================================================

set(_gpu_sources_present TRUE)
foreach(_src ${CONSENSUS_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
        set(_gpu_sources_present FALSE)
        break()
    endif()
endforeach()

if(_gpu_sources_present AND LUX_GPU_INCLUDE)
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

    if(APPLE)
        set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".dylib")
    elseif(WIN32)
        set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".dll")
    else()
        set_target_properties(luxconsensus_gpu PROPERTIES SUFFIX ".so")
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/consensus_c_api.cpp")
        add_library(luxconsensus_gpu_c SHARED src/consensus_c_api.cpp)
        target_link_libraries(luxconsensus_gpu_c PRIVATE luxconsensus_gpu)
        target_include_directories(luxconsensus_gpu_c PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        )
        install(TARGETS luxconsensus_gpu_c
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()

    install(TARGETS luxconsensus_gpu
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# =============================================================================
# Consensus Harness Library (imported from luxfi/consensus/pkg/cpp/)
# =============================================================================
#
# E2E test/bench harness, NOT a production transport. Pulls in ZeroMQ
# (libzmq3-dev) via src/network.cpp — production node-to-node transport
# is ZAP (github.com/luxfi/zap), not ZMQ. This harness exists only for
# the C++ e2e-test scaffold under luxfi/consensus/test/e2e/.
#
# Header paths still reference flat names (lux_consensus.h vs the luxcpp
# nested lux/consensus.hpp); also uses C++20 std::span. Needs a port pass
# before it will build cleanly here — opt-in once that work is done.

option(LUX_CONSENSUS_BUILD_ZMQ_HARNESS
    "Build imported ZMQ-based consensus test harness (NOT for production; ZAP is canonical)"
    OFF)

if(LUX_CONSENSUS_BUILD_ZMQ_HARNESS)
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
        target_compile_features(luxconsensus_harness PUBLIC cxx_std_20)
        set_target_properties(luxconsensus_harness PROPERTIES
            OUTPUT_NAME "luxconsensus_harness"
            VERSION ${PROJECT_VERSION}
        )
        install(TARGETS luxconsensus_harness
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif()
endif()

install(DIRECTORY include/lux
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "=== Lux Consensus Configuration ===")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Quasar:         ${LUX_CONSENSUS_BUILD_QUASAR}")
if(LUX_GPU_INCLUDE)
    message(STATUS "  GPU Include:    ${LUX_GPU_INCLUDE}")
else()
    message(STATUS "  GPU Include:    (disabled)")
endif()
message(STATUS "  Build Tests:    ${LUX_CONSENSUS_BUILD_TESTS}")
message(STATUS "")
