// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "lux/consensus.hpp"
#include <algorithm>
#include <vector>

namespace lux::consensus {

// Batch vote processing utilities for performance optimization.
// These functions enable processing multiple votes efficiently.

/// Process multiple votes in a batch, returning the count of successfully processed votes.
inline size_t process_vote_batch(
    Chain& chain,
    const std::vector<Vote>& votes
) {
    size_t processed = 0;
    for (const auto& vote : votes) {
        if (chain.record_vote(vote)) {
            processed++;
        }
    }
    return processed;
}

/// Filter votes by block ID before processing.
inline std::vector<Vote> filter_votes_by_block(
    const std::vector<Vote>& votes,
    const std::array<uint8_t, 32>& block_id
) {
    std::vector<Vote> filtered;
    filtered.reserve(votes.size());

    std::copy_if(
        votes.begin(),
        votes.end(),
        std::back_inserter(filtered),
        [&block_id](const Vote& v) {
            return v.block_id == block_id;
        }
    );

    return filtered;
}

/// Count votes by type for a specific block.
inline std::pair<size_t, size_t> count_votes_by_type(
    const std::vector<Vote>& votes,
    const std::array<uint8_t, 32>& block_id
) {
    size_t prefer_count = 0;
    size_t reject_count = 0;

    for (const auto& vote : votes) {
        if (vote.block_id == block_id) {
            switch (vote.type) {
                case VoteType::Prefer:
                case VoteType::Accept:
                    prefer_count++;
                    break;
                case VoteType::Reject:
                    reject_count++;
                    break;
            }
        }
    }

    return {prefer_count, reject_count};
}

/// Check if a quorum threshold is met for a block.
inline bool check_quorum(
    const std::vector<Vote>& votes,
    const std::array<uint8_t, 32>& block_id,
    size_t threshold
) {
    auto [prefer, reject] = count_votes_by_type(votes, block_id);
    return prefer >= threshold;
}

} // namespace lux::consensus
