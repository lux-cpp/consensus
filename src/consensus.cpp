#include <lux/consensus.hpp>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>

namespace lux::consensus {

// Block serialization
// Fix C-001: include timestamp in serialization to match corrected deserialize
std::vector<uint8_t> Block::serialize() const {
    std::vector<uint8_t> result;
    result.reserve(sizeof(id) + sizeof(parent_id) + sizeof(height) + sizeof(uint64_t) + payload.size());

    // Add id
    result.insert(result.end(), id.begin(), id.end());

    // Add parent_id
    result.insert(result.end(), parent_id.begin(), parent_id.end());

    // Add height
    const uint8_t* height_ptr = reinterpret_cast<const uint8_t*>(&height);
    result.insert(result.end(), height_ptr, height_ptr + sizeof(height));

    // Add timestamp
    auto epoch = timestamp.time_since_epoch();
    uint64_t timestamp_secs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(epoch).count());
    const uint8_t* ts_ptr = reinterpret_cast<const uint8_t*>(&timestamp_secs);
    result.insert(result.end(), ts_ptr, ts_ptr + sizeof(timestamp_secs));

    // Add payload
    result.insert(result.end(), payload.begin(), payload.end());

    return result;
}

// Block hash (simplified)
std::array<uint8_t, 32> Block::hash() const {
    std::array<uint8_t, 32> result{};
    auto serialized = serialize();

    // XOR-fold hash for block identification
    // For cryptographic verification, use the signature field
    for (size_t i = 0; i < serialized.size(); ++i) {
        result[i % 32] ^= serialized[i];
    }

    return result;
}

// Block deserialization
// Fix C-001: buffer size check corrected per LUX-SEC-REMEDIATION-2026
// Minimum is 32 (id) + 32 (parent_id) + 8 (height) + 8 (timestamp) = 80
Block Block::deserialize(std::span<const uint8_t> data) {
    Block block;

    if (data.size() < 80) { // minimum: 32 + 32 + 8 + 8
        return block;
    }

    // Read id
    std::copy_n(data.begin(), 32, block.id.begin());

    // Read parent_id
    std::copy_n(data.begin() + 32, 32, block.parent_id.begin());

    // Read height
    std::memcpy(&block.height, data.data() + 64, sizeof(block.height));

    // Read timestamp
    uint64_t timestamp_secs = 0;
    std::memcpy(&timestamp_secs, data.data() + 72, sizeof(timestamp_secs));
    block.timestamp = std::chrono::system_clock::time_point(
        std::chrono::seconds(timestamp_secs));

    // Read payload
    if (data.size() > 80) {
        block.payload.assign(data.begin() + 80, data.end());
    }

    return block;
}

// Vote packing - compact 8-byte representation
std::array<uint8_t, 8> Vote::pack() const noexcept {
    std::array<uint8_t, 8> result{};

    // First 3 bytes: hash of node_id
    result[0] = node_id[0];
    result[1] = node_id[1];
    result[2] = node_id[2];

    // Next 3 bytes: hash of block_id
    result[3] = block_id[0];
    result[4] = block_id[1];
    result[5] = block_id[2];

    // Vote type
    result[6] = static_cast<uint8_t>(type);

    // Reserved
    result[7] = 0;

    return result;
}

// Vote unpacking
Vote Vote::unpack(std::span<const uint8_t, 8> data) noexcept {
    Vote vote{};

    // Restore partial node_id
    vote.node_id[0] = data[0];
    vote.node_id[1] = data[1];
    vote.node_id[2] = data[2];

    // Restore partial block_id
    vote.block_id[0] = data[3];
    vote.block_id[1] = data[4];
    vote.block_id[2] = data[5];

    // Vote type
    vote.type = static_cast<VoteType>(data[6]);

    return vote;
}

// Chain implementation
class ChainImpl {
private:
    Config config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Block> blocks_;
    std::unordered_map<std::string, Status> block_status_;
    std::unordered_map<std::string, std::vector<Vote>> votes_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> blocks_accepted_{0};
    std::atomic<uint64_t> blocks_rejected_{0};
    std::atomic<uint64_t> votes_processed_{0};
    Chain::DecisionCallback decision_callback_;

    static std::string to_key(const std::array<uint8_t, 32>& arr) {
        return std::string(reinterpret_cast<const char*>(arr.data()), arr.size());
    }

    void check_decision(const std::string& key) {
        auto it = votes_.find(key);
        if (it == votes_.end()) return;

        size_t prefer_count = 0;
        size_t reject_count = 0;

        for (const auto& vote : it->second) {
            if (vote.type == VoteType::Prefer || vote.type == VoteType::Accept) {
                prefer_count++;
            } else if (vote.type == VoteType::Reject) {
                reject_count++;
            }
        }

        // Check against alpha threshold
        if (prefer_count >= config_.alpha) {
            block_status_[key] = Status::Accepted;
            blocks_accepted_.fetch_add(1, std::memory_order_relaxed);

            if (decision_callback_) {
                std::array<uint8_t, 32> block_id;
                std::copy(key.begin(), key.end(), block_id.begin());
                decision_callback_(block_id, Decision::Accept);
            }
        } else if (reject_count >= config_.alpha) {
            block_status_[key] = Status::Rejected;
            blocks_rejected_.fetch_add(1, std::memory_order_relaxed);

            if (decision_callback_) {
                std::array<uint8_t, 32> block_id;
                std::copy(key.begin(), key.end(), block_id.begin());
                decision_callback_(block_id, Decision::Reject);
            }
        }
    }

public:
    explicit ChainImpl(const Config& config) : config_(config) {}

    bool start() {
        running_.store(true, std::memory_order_release);
        return true;
    }

    void stop() {
        running_.store(false, std::memory_order_release);
    }

    bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    bool add(const Block& block) {
        std::lock_guard lock(mutex_);
        auto key = to_key(block.id);

        if (blocks_.find(key) != blocks_.end()) {
            return false; // Already exists
        }

        blocks_[key] = block;
        block_status_[key] = Status::Processing;
        return true;
    }

    Status get_status(const std::array<uint8_t, 32>& block_id) const {
        std::lock_guard lock(mutex_);
        auto key = to_key(block_id);
        auto it = block_status_.find(key);
        return it != block_status_.end() ? it->second : Status::Unknown;
    }

    std::optional<Block> get_block(const std::array<uint8_t, 32>& block_id) const {
        std::lock_guard lock(mutex_);
        auto key = to_key(block_id);
        auto it = blocks_.find(key);
        return it != blocks_.end() ? std::optional<Block>(it->second) : std::nullopt;
    }

    bool record_vote(const Vote& vote) {
        std::lock_guard lock(mutex_);
        auto key = to_key(vote.block_id);

        // Check if block exists
        if (blocks_.find(key) == blocks_.end()) {
            return false;
        }

        votes_[key].push_back(vote);
        votes_processed_.fetch_add(1, std::memory_order_relaxed);

        check_decision(key);
        return true;
    }

    Decision get_decision(const std::array<uint8_t, 32>& block_id) const {
        auto status = get_status(block_id);
        switch (status) {
            case Status::Accepted: return Decision::Accept;
            case Status::Rejected: return Decision::Reject;
            default: return Decision::Unknown;
        }
    }

    uint64_t blocks_accepted() const noexcept {
        return blocks_accepted_.load(std::memory_order_relaxed);
    }

    uint64_t blocks_rejected() const noexcept {
        return blocks_rejected_.load(std::memory_order_relaxed);
    }

    uint64_t votes_processed() const noexcept {
        return votes_processed_.load(std::memory_order_relaxed);
    }

    void set_decision_callback(Chain::DecisionCallback cb) {
        decision_callback_ = std::move(cb);
    }
};

// Chain class implementation
Chain::Chain(const Config& config) : impl(std::make_unique<ChainImpl>(config)) {}

Chain::~Chain() = default;

Chain::Chain(Chain&&) noexcept = default;
Chain& Chain::operator=(Chain&&) noexcept = default;

bool Chain::start() {
    return impl->start();
}

void Chain::stop() {
    impl->stop();
}

bool Chain::is_running() const noexcept {
    return impl->is_running();
}

bool Chain::add(const Block& block) {
    return impl->add(block);
}

Status Chain::get_status(const std::array<uint8_t, 32>& block_id) const {
    return impl->get_status(block_id);
}

std::optional<Block> Chain::get_block(const std::array<uint8_t, 32>& block_id) const {
    return impl->get_block(block_id);
}

bool Chain::record_vote(const Vote& vote) {
    return impl->record_vote(vote);
}

Decision Chain::get_decision(const std::array<uint8_t, 32>& block_id) const {
    return impl->get_decision(block_id);
}

uint64_t Chain::blocks_accepted() const noexcept {
    return impl->blocks_accepted();
}

uint64_t Chain::blocks_rejected() const noexcept {
    return impl->blocks_rejected();
}

uint64_t Chain::votes_processed() const noexcept {
    return impl->votes_processed();
}

void Chain::set_decision_callback(DecisionCallback cb) {
    impl->set_decision_callback(std::move(cb));
}

} // namespace lux::consensus
