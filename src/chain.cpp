// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "lux/consensus.hpp"
#include <stdexcept>
#include <cstring>
#include <random>

// Include C SDK for backend implementation
extern "C" {
#include "lux_consensus.h"
}

namespace lux::consensus {

// ChainImpl - private implementation using C SDK
class ChainImpl {
public:
    lux_chain_t* chain = nullptr;
    Config config;
    bool running = false;
    
    // Statistics
    uint64_t blocks_accepted_count = 0;
    uint64_t blocks_rejected_count = 0;
    uint64_t votes_processed_count = 0;
    
    // Callback
    Chain::DecisionCallback decision_callback;
    
    ChainImpl(const Config& cfg) : config(cfg) {
        // Convert C++ config to C config
        lux_config_t c_config{};
        c_config.node_count = static_cast<uint32_t>(cfg.node_count);
        c_config.k = static_cast<uint32_t>(cfg.k);
        c_config.alpha = static_cast<uint32_t>(cfg.alpha);
        c_config.beta = static_cast<uint32_t>(cfg.beta);
        
        // Create chain using C SDK
        chain = lux_chain_new(&c_config);
        if (!chain) {
            throw std::runtime_error("Failed to create chain");
        }
    }
    
    ~ChainImpl() {
        if (chain) {
            lux_chain_destroy(chain);
        }
    }
};

// Chain implementation

Chain::Chain(const Config& config) 
    : impl(std::make_unique<ChainImpl>(config)) {}

Chain::~Chain() = default;

Chain::Chain(Chain&&) noexcept = default;
Chain& Chain::operator=(Chain&&) noexcept = default;

bool Chain::start() {
    if (impl->running) {
        return false;
    }
    
    auto err = lux_chain_start(impl->chain);
    if (err != LUX_SUCCESS) {
        return false;
    }
    
    impl->running = true;
    return true;
}

void Chain::stop() {
    if (impl->running) {
        lux_chain_stop(impl->chain);
        impl->running = false;
    }
}

bool Chain::is_running() const noexcept {
    return impl->running;
}

bool Chain::add(const Block& block) {
    if (!impl->running) {
        return false;
    }
    
    // Convert C++ block to C block
    lux_block_t c_block{};
    std::memcpy(c_block.id, block.id.data(), 32);
    std::memcpy(c_block.parent_id, block.parent_id.data(), 32);
    c_block.height = block.height;
    
    // Convert timestamp to unix timestamp
    auto epoch = block.timestamp.time_since_epoch();
    c_block.timestamp = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
    
    // Payload (simplified - in real impl would handle properly)
    c_block.data = const_cast<uint8_t*>(block.payload.data());
    c_block.data_size = block.payload.size();
    
    auto err = lux_chain_add_block(impl->chain, &c_block);
    if (err != LUX_SUCCESS) {
        return false;
    }
    
    impl->blocks_accepted_count++;
    
    // Trigger callback if set
    if (impl->decision_callback) {
        impl->decision_callback(block.id, Decision::Accept);
    }
    
    return true;
}

Status Chain::get_status(const std::array<uint8_t, 32>& block_id) const {
    // Query C SDK for status
    // For now, return simplified status based on whether block was added
    return impl->running ? Status::Processing : Status::Unknown;
}

std::optional<Block> Chain::get_block(const std::array<uint8_t, 32>& block_id) const {
    // In a real implementation, we'd query the C SDK
    // For now, return empty optional
    return std::nullopt;
}

bool Chain::record_vote(const Vote& vote) {
    if (!impl->running) {
        return false;
    }
    
    impl->votes_processed_count++;
    return true;
}

Decision Chain::get_decision(const std::array<uint8_t, 32>& block_id) const {
    // Query decision from C SDK
    // For now, return Accept if running
    return impl->running ? Decision::Accept : Decision::Unknown;
}

uint64_t Chain::blocks_accepted() const noexcept {
    return impl->blocks_accepted_count;
}

uint64_t Chain::blocks_rejected() const noexcept {
    return impl->blocks_rejected_count;
}

uint64_t Chain::votes_processed() const noexcept {
    return impl->votes_processed_count;
}

void Chain::set_decision_callback(DecisionCallback cb) {
    impl->decision_callback = std::move(cb);
}

// Block implementation

std::vector<uint8_t> Block::serialize() const {
    std::vector<uint8_t> result;
    result.reserve(32 + 32 + 8 + 8 + payload.size());
    
    // ID
    result.insert(result.end(), id.begin(), id.end());
    
    // Parent ID
    result.insert(result.end(), parent_id.begin(), parent_id.end());
    
    // Height (8 bytes, little-endian)
    for (int i = 0; i < 8; i++) {
        result.push_back(static_cast<uint8_t>((height >> (i * 8)) & 0xFF));
    }
    
    // Timestamp (8 bytes)
    auto epoch = timestamp.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
    for (int i = 0; i < 8; i++) {
        result.push_back(static_cast<uint8_t>((seconds >> (i * 8)) & 0xFF));
    }
    
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

std::array<uint8_t, 32> Block::hash() const {
    // Simple hash implementation using serialize
    auto serialized = serialize();
    
    // Use a simple hash for now (in real impl, use SHA256)
    std::array<uint8_t, 32> hash{};
    for (size_t i = 0; i < serialized.size(); i++) {
        hash[i % 32] ^= serialized[i];
    }
    
    return hash;
}

Block Block::deserialize(std::span<const uint8_t> data) {
    if (data.size() < 80) {
        throw std::runtime_error("Invalid block data: too small");
    }
    
    Block block;
    
    // ID
    std::copy_n(data.begin(), 32, block.id.begin());
    
    // Parent ID
    std::copy_n(data.begin() + 32, 32, block.parent_id.begin());
    
    // Height
    block.height = 0;
    for (int i = 0; i < 8; i++) {
        block.height |= static_cast<uint64_t>(data[64 + i]) << (i * 8);
    }
    
    // Timestamp
    uint64_t seconds = 0;
    for (int i = 0; i < 8; i++) {
        seconds |= static_cast<uint64_t>(data[72 + i]) << (i * 8);
    }
    block.timestamp = std::chrono::system_clock::time_point(
        std::chrono::seconds(seconds)
    );
    
    // Payload
    if (data.size() > 80) {
        block.payload.assign(data.begin() + 80, data.end());
    }
    
    return block;
}

// Vote implementation

std::array<uint8_t, 8> Vote::pack() const noexcept {
    std::array<uint8_t, 8> result{};
    
    // Pack: [node_id_hash(4)] [block_id_hash(4)] [type(1)] [padding(3)]
    // Use first 4 bytes of node_id
    std::copy_n(node_id.begin(), 4, result.begin());
    
    // Use first 3 bytes of block_id  
    std::copy_n(block_id.begin(), 3, result.begin() + 4);
    
    // Vote type
    result[7] = static_cast<uint8_t>(type);
    
    return result;
}

Vote Vote::unpack(std::span<const uint8_t, 8> data) noexcept {
    Vote vote;
    
    // Unpack node_id (first 4 bytes, rest zeros)
    std::copy_n(data.begin(), 4, vote.node_id.begin());
    
    // Unpack block_id (next 3 bytes, rest zeros)
    std::copy_n(data.begin() + 4, 3, vote.block_id.begin());
    
    // Unpack type
    vote.type = static_cast<VoteType>(data[7]);
    
    return vote;
}

} // namespace lux::consensus