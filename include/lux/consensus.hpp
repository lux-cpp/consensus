#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <optional>
#include <chrono>
#include <functional>
#include <span>
#include <array>

namespace lux::consensus {

// Forward declarations
class Chain;
class ChainImpl;

// Block status
enum class Status : uint8_t {
    Unknown = 0,
    Processing = 1,
    Accepted = 2,
    Rejected = 3
};

// Vote types
enum class VoteType : uint8_t {
    Prefer = 1,
    Accept = 2,
    Reject = 3
};

// Decision
enum class Decision : uint8_t {
    Unknown = 0,
    Accept = 1,
    Reject = 2
};

// Simple configuration
struct Config {
    size_t node_count = 1;           // Number of nodes in network
    size_t k = 0;                    // Sample size (0 for auto)
    size_t alpha = 0;                // Quorum size (0 for auto)
    size_t beta = 0;                 // Decision threshold (0 for auto)
    
    // Factory methods for common configurations
    [[nodiscard]] static Config single_validator() noexcept;
    [[nodiscard]] static Config local_network() noexcept;
    [[nodiscard]] static Config testnet() noexcept;
    [[nodiscard]] static Config mainnet() noexcept;
    [[nodiscard]] static Config custom(size_t nodes) noexcept;
};

// Block structure
struct Block {
    std::array<uint8_t, 32> id;
    std::array<uint8_t, 32> parent_id;
    uint64_t height;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> payload;
    
    [[nodiscard]] std::vector<uint8_t> serialize() const;
    [[nodiscard]] std::array<uint8_t, 32> hash() const;
    
    static Block deserialize(std::span<const uint8_t> data);
};

// Vote structure
struct Vote {
    std::array<uint8_t, 32> node_id;
    std::array<uint8_t, 32> block_id;
    VoteType type;
    
    // Binary protocol (8 bytes compact)
    [[nodiscard]] std::array<uint8_t, 8> pack() const noexcept;
    static Vote unpack(std::span<const uint8_t, 8> data) noexcept;
};

// Context for consensus operations
struct Context {
    std::array<uint8_t, 32> node_id;
    uint32_t network_id;
    std::chrono::milliseconds timeout{30000};
};

// Main Chain class - simplified single-import API
class Chain {
public:
    // Constructors
    Chain() : Chain(Config::single_validator()) {}
    explicit Chain(const Config& config);
    ~Chain();
    
    // Non-copyable, movable
    Chain(const Chain&) = delete;
    Chain& operator=(const Chain&) = delete;
    Chain(Chain&&) noexcept;
    Chain& operator=(Chain&&) noexcept;
    
    // Lifecycle
    [[nodiscard]] bool start();
    void stop();
    [[nodiscard]] bool is_running() const noexcept;
    
    // Block operations
    [[nodiscard]] bool add(const Block& block);
    [[nodiscard]] Status get_status(const std::array<uint8_t, 32>& block_id) const;
    [[nodiscard]] std::optional<Block> get_block(const std::array<uint8_t, 32>& block_id) const;
    
    // Voting
    [[nodiscard]] bool record_vote(const Vote& vote);
    [[nodiscard]] Decision get_decision(const std::array<uint8_t, 32>& block_id) const;
    
    // Statistics
    [[nodiscard]] uint64_t blocks_accepted() const noexcept;
    [[nodiscard]] uint64_t blocks_rejected() const noexcept;
    [[nodiscard]] uint64_t votes_processed() const noexcept;
    
    // Callbacks (optional)
    using DecisionCallback = std::function<void(const std::array<uint8_t, 32>&, Decision)>;
    void set_decision_callback(DecisionCallback cb);
    
private:
    std::unique_ptr<ChainImpl> impl;
};

// Helper functions
[[nodiscard]] inline Config default_config() {
    return Config::single_validator();
}

[[nodiscard]] inline std::unique_ptr<Chain> new_chain(const Config& config = default_config()) {
    return std::make_unique<Chain>(config);
}

// Implementation of Config factory methods
inline Config Config::single_validator() noexcept {
    return Config{1, 1, 1, 1};
}

inline Config Config::local_network() noexcept {
    return Config{5, 3, 3, 4};
}

inline Config Config::testnet() noexcept {
    return Config{20, 10, 14, 20};
}

inline Config Config::mainnet() noexcept {
    return Config{100, 20, 15, 20};
}

inline Config Config::custom(size_t nodes) noexcept {
    Config cfg{nodes};
    // Auto-calculate optimal parameters based on network size
    if (nodes == 1) {
        cfg.k = cfg.alpha = cfg.beta = 1;
    } else if (nodes <= 5) {
        cfg.k = 3;
        cfg.alpha = 3;
        cfg.beta = 4;
    } else if (nodes <= 20) {
        cfg.k = nodes / 2;
        cfg.alpha = (nodes * 2) / 3;
        cfg.beta = nodes - 2;
    } else {
        cfg.k = 20;
        cfg.alpha = 15;
        cfg.beta = 20;
    }
    return cfg;
}

} // namespace lux::consensus