#include <lux/consensus.hpp>
#include <iostream>
#include <cassert>

using namespace lux::consensus;

void test_basic_chain() {
    // Create a chain with default config
    Config config = Config::local_network();
    Chain chain(config);

    // Start the chain
    assert(chain.start());
    assert(chain.is_running());

    // Create a block
    Block block{};
    block.id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    block.parent_id = {};  // Genesis has no parent
    block.height = 1;
    block.timestamp = std::chrono::system_clock::now();
    block.payload = {0x01, 0x02, 0x03};

    // Add block
    assert(chain.add(block));

    // Check status
    assert(chain.get_status(block.id) == Status::Processing);

    // Simulate votes (need alpha votes to accept)
    for (size_t i = 0; i < config.alpha; ++i) {
        Vote vote{};
        vote.node_id[0] = static_cast<uint8_t>(i);
        vote.block_id = block.id;
        vote.type = VoteType::Prefer;
        chain.record_vote(vote);
    }

    // Check decision
    assert(chain.get_decision(block.id) == Decision::Accept);
    assert(chain.blocks_accepted() == 1);

    // Stop the chain
    chain.stop();
    assert(!chain.is_running());

    std::cout << "✅ Basic chain test passed\n";
}

void test_block_serialization() {
    Block block{};
    block.id.fill(0xAA);
    block.parent_id.fill(0xBB);
    block.height = 12345;
    block.payload = {1, 2, 3, 4, 5};

    auto serialized = block.serialize();
    assert(serialized.size() >= 72);  // 32 + 32 + 8

    auto deserialized = Block::deserialize(serialized);
    assert(deserialized.id == block.id);
    assert(deserialized.parent_id == block.parent_id);
    assert(deserialized.height == block.height);

    std::cout << "✅ Block serialization test passed\n";
}

void test_vote_packing() {
    Vote vote{};
    vote.node_id[0] = 0x11;
    vote.node_id[1] = 0x22;
    vote.node_id[2] = 0x33;
    vote.block_id[0] = 0xAA;
    vote.block_id[1] = 0xBB;
    vote.block_id[2] = 0xCC;
    vote.type = VoteType::Accept;

    auto packed = vote.pack();
    assert(packed.size() == 8);
    assert(packed[0] == 0x11);
    assert(packed[6] == static_cast<uint8_t>(VoteType::Accept));

    auto unpacked = Vote::unpack(packed);
    assert(unpacked.node_id[0] == vote.node_id[0]);
    assert(unpacked.block_id[0] == vote.block_id[0]);
    assert(unpacked.type == vote.type);

    std::cout << "✅ Vote packing test passed\n";
}

void test_config_factory() {
    auto single = Config::single_validator();
    assert(single.node_count == 1);
    assert(single.k == 1);

    auto local = Config::local_network();
    assert(local.node_count == 5);
    assert(local.k == 3);

    auto testnet = Config::testnet();
    assert(testnet.node_count == 20);

    auto mainnet = Config::mainnet();
    assert(mainnet.node_count == 100);

    auto custom = Config::custom(10);
    assert(custom.node_count == 10);

    std::cout << "✅ Config factory test passed\n";
}

int main() {
    std::cout << "Running Lux Consensus C++ SDK tests...\n\n";

    test_config_factory();
    test_block_serialization();
    test_vote_packing();
    test_basic_chain();

    std::cout << "\n✅ All tests passed!\n";
    return 0;
}
