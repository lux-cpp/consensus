#pragma once

#include "consensus.hpp"
#include <optional>
#include <span>

#ifdef HAS_MLX
#include <mlx/mlx.h>
#endif

namespace lux {
namespace consensus {

#ifdef HAS_MLX

/**
 * @brief MLX-accelerated consensus engine for Apple Silicon
 *
 * Provides GPU-accelerated batch processing of votes and blocks
 * using Apple's MLX framework. Automatically falls back to CPU
 * if GPU is unavailable.
 */
class MLXConsensus {
public:
    /**
     * @brief Configuration for MLX GPU acceleration
     */
    struct MLXConfig {
        std::string model_path;           ///< Path to pre-trained model
        std::string device_type = "gpu";  ///< "gpu" or "cpu"
        size_t batch_size = 32;           ///< Optimal batch size for GPU
        bool enable_quantization = true;  ///< Use int8 quantization
        size_t cache_size = 5000;         ///< Number of blocks to cache on GPU
        size_t parallel_ops = 8;          ///< Number of parallel Metal compute pipelines
    };

    /**
     * @brief Initialize MLX backend with configuration
     * @param config MLX configuration
     * @throws std::runtime_error if MLX initialization fails
     */
    explicit MLXConsensus(const MLXConfig& config);

    /**
     * @brief Destructor - cleans up GPU resources
     */
    ~MLXConsensus();

    // Disable copy, allow move
    MLXConsensus(const MLXConsensus&) = delete;
    MLXConsensus& operator=(const MLXConsensus&) = delete;
    MLXConsensus(MLXConsensus&&) noexcept;
    MLXConsensus& operator=(MLXConsensus&&) noexcept;

    /**
     * @brief Process a batch of votes on GPU
     * @param votes Vector of votes to process
     * @return Number of votes successfully processed
     */
    size_t process_votes_batch(std::span<const Vote> votes);

    /**
     * @brief Validate a batch of block IDs on GPU
     * @param block_ids Vector of 32-byte block IDs to validate
     * @return Vector of validation results (true = valid)
     */
    std::vector<bool> validate_blocks_batch(
        std::span<const std::array<uint8_t, 32>> block_ids);

    /**
     * @brief Check if GPU is available and active
     * @return true if using GPU, false if CPU fallback
     */
    bool is_gpu_enabled() const noexcept { return gpu_enabled_; }

    /**
     * @brief Get current GPU memory usage
     * @return Memory usage in bytes
     */
    size_t get_gpu_memory_usage() const;

    /**
     * @brief Get peak GPU memory usage
     * @return Peak memory usage in bytes
     */
    size_t get_peak_gpu_memory() const;

    /**
     * @brief Reset peak memory counter
     */
    void reset_peak_memory();

    /**
     * @brief Get GPU device name
     * @return Device name string (e.g., "Apple M3 Max GPU")
     */
    std::string get_device_name() const;

    /**
     * @brief Enable GPU profiling/tracing
     * @param enable true to enable, false to disable
     */
    void set_profiling(bool enable);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
    bool gpu_enabled_ = false;
    MLXConfig config_;

    // Internal batch processing
    void preprocess_batch(std::span<const Vote> votes, mlx::core::array& out);
    mlx::core::array forward_pass(const mlx::core::array& input);
    std::vector<bool> postprocess_results(const mlx::core::array& output);
};

/**
 * @brief Adaptive batch processor with automatic batch size tuning
 *
 * Automatically adjusts batch size based on GPU performance
 * to maximize throughput.
 */
class AdaptiveMLXBatchProcessor {
public:
    explicit AdaptiveMLXBatchProcessor(std::unique_ptr<MLXConsensus> mlx);

    /**
     * @brief Add vote to buffer (auto-flushes when optimal)
     * @param vote Vote to process
     */
    void add_vote(const Vote& vote);

    /**
     * @brief Flush buffered votes to GPU
     */
    void flush();

    /**
     * @brief Get current optimal batch size
     * @return Current batch size
     */
    size_t get_batch_size() const noexcept { return optimal_batch_size_; }

    /**
     * @brief Get processing statistics
     * @return Throughput in votes/second
     */
    double get_throughput() const noexcept { return throughput_; }

private:
    std::unique_ptr<MLXConsensus> mlx_;
    std::vector<Vote> vote_buffer_;
    size_t optimal_batch_size_ = 32;
    double throughput_ = 0.0;

    void adjust_batch_size(double current_throughput);
};

#endif // HAS_MLX

} // namespace consensus
} // namespace lux
