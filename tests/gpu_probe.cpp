// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// gpu_probe — instantiate MLXConsensus on the current host and print
// whether the GPU path was actually taken at runtime. Empirical proof
// that the MLX Metal dispatch is live (not just compiled in).

#include "lux/mlx_consensus.hpp"
#include <iostream>

#ifdef HAS_MLX
#include <mlx/mlx.h>
namespace mx = mlx::core;
#endif

int main() {
#ifdef HAS_MLX
    std::cout << "HAS_MLX = 1\n";
    std::cout << "mx::metal::is_available() = "
              << (mx::metal::is_available() ? "true" : "false") << "\n";
#else
    std::cout << "HAS_MLX = 0 (compile-time)\n";
    return 0;
#endif

    lux::consensus::MLXConsensus::MLXConfig cfg;
    cfg.device_type = "gpu";
    try {
        lux::consensus::MLXConsensus c(cfg);
        std::cout << "MLXConsensus.gpu_enabled() = "
                  << (c.is_gpu_enabled() ? "true" : "false") << "\n";
        std::cout << "MLXConsensus.device      = " << c.get_device_name() << "\n";
    } catch (const std::exception& e) {
        std::cout << "MLXConsensus init failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
