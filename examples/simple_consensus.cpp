#include <lux/consensus.hpp>
#include <iostream>

int main() {
    using namespace lux::consensus;
    
    // Configure consensus
    ConsensusParams params{
        .k = 20,
        .alpha_preference = 15,
        .alpha_confidence = 15,
        .beta = 20,
        .concurrent_polls = 10,
        .max_outstanding_items = 1000
    };
    
    // Create consensus engine
    auto consensus = Consensus::create(EngineType::Snowball, params);
    if (!consensus) {
        std::cerr << "Failed to create consensus\n";
        return 1;
    }
    
    // Set up event handler
    consensus->on_block_accepted([](uint16_t block_id) {
        std::cout << "✅ Block " << block_id << " accepted!\n";
    });
    
    // Create and add a block
    Block block{
        .id = 0x1234,
        .parent_id = 0x0000,
        .height = 1,
        .timestamp = std::chrono::system_clock::now(),
        .data = {0x01, 0x02, 0x03, 0x04}
    };
    
    consensus->add_block(block);
    std::cout << "Added block " << std::hex << block.id << "\n";
    
    // Simulate voting
    std::cout << "Processing votes...\n";
    for (int i = 0; i < 20; ++i) {
        Vote vote{
            .engine_type = EngineType::Snowball,
            .node_id = static_cast<uint16_t>(i),
            .block_id = 0x1234,
            .vote_type = VoteType::Prefer
        };
        consensus->process_vote(vote);
    }
    
    // Check consensus
    if (consensus->is_accepted(0x1234)) {
        std::cout << "Block 0x" << std::hex << 0x1234 
                  << " achieved consensus!\n";
    }
    
    // Print statistics
    auto stats = consensus->get_stats();
    std::cout << "\nStatistics:\n";
    std::cout << "  Votes processed: " << stats.votes_processed << "\n";
    std::cout << "  Blocks accepted: " << stats.blocks_accepted << "\n";
    std::cout << "  Blocks rejected: " << stats.blocks_rejected << "\n";
    
    return 0;
}