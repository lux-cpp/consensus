#include "lux/consensus.hpp"

#ifdef HAS_MLX
#include "lux/mlx_consensus.hpp"
#endif

#include <chrono>
#include <iostream>
#include <random>
#include <vector>

using namespace lux::consensus;

int main() {
#ifdef HAS_MLX
    std::cout << "=== Lux Consensus MLX GPU Acceleration Demo ===\n\n";

    // Configure MLX
    MLXConsensus::MLXConfig mlx_config{
        .model_path = "/models/consensus/mlx_model.bin",
        .device_type = "gpu",
        .batch_size = 32,
        .enable_quantization = true,
        .cache_size = 5000,
        .parallel_ops = 8
    };

    try {
        // Create MLX consensus engine
        auto mlx = std::make_unique<MLXConsensus>(mlx_config);

        std::cout << "Device: " << mlx->get_device_name() << "\n";
        std::cout << "GPU Enabled: " << (mlx->is_gpu_enabled() ? "Yes" : "No") << "\n\n";

        // Generate test votes
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        auto generate_vote = [&]() -> Vote {
            Vote vote;
            for (auto& byte : vote.voter_id.data) byte = dist(gen);
            for (auto& byte : vote.block_id.data) byte = dist(gen);
            vote.is_preference = (dist(gen) % 2) == 0;
            return vote;
        };

        // Benchmark different batch sizes
        std::vector<size_t> batch_sizes = {10, 100, 1000, 10000};

        std::cout << "Performance Benchmarks:\n";
        std::cout << "=======================\n\n";

        for (auto batch_size : batch_sizes) {
            std::vector<Vote> votes;
            votes.reserve(batch_size);
            for (size_t i = 0; i < batch_size; ++i) {
                votes.push_back(generate_vote());
            }

            // Warm-up
            mlx->process_votes_batch(votes);

            // Benchmark
            auto start = std::chrono::high_resolution_clock::now();
            auto processed = mlx->process_votes_batch(votes);
            auto end = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            double throughput = batch_size * 1000000.0 / duration.count();

            std::cout << "Batch Size: " << batch_size << "\n";
            std::cout << "  Time: " << duration.count() << " μs\n";
            std::cout << "  Throughput: " << static_cast<size_t>(throughput) << " votes/sec\n";
            std::cout << "  Per-vote: " << (duration.count() / batch_size) << " ns\n";
            std::cout << "  Processed: " << processed << "/" << batch_size << "\n\n";
        }

        // Memory usage
        std::cout << "GPU Memory Usage:\n";
        std::cout << "  Active: " << (mlx->get_gpu_memory_usage() / (1024 * 1024)) << " MB\n";
        std::cout << "  Peak: " << (mlx->get_peak_gpu_memory() / (1024 * 1024)) << " MB\n\n";

        // Test adaptive batch processor
        std::cout << "Testing Adaptive Batch Processor:\n";
        std::cout << "==================================\n\n";

        AdaptiveMLXBatchProcessor processor(std::move(mlx));

        auto start = std::chrono::high_resolution_clock::now();

        // Process 10,000 votes with adaptive batching
        for (size_t i = 0; i < 10000; ++i) {
            processor.add_vote(generate_vote());
        }
        processor.flush();

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "Total time: " << duration.count() << " μs\n";
        std::cout << "Throughput: " << static_cast<size_t>(processor.get_throughput()) << " votes/sec\n";
        std::cout << "Optimal batch size: " << processor.get_batch_size() << "\n\n";

        std::cout << "✅ MLX GPU acceleration working!\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

#else
    std::cout << "MLX support not enabled. Build with -DHAS_MLX=ON\n";
    return 1;
#endif
}
