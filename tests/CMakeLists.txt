# Tests CMakeLists.txt
add_executable(test_consensus test_consensus.cpp)

# Link against lux_consensus library
target_link_libraries(test_consensus PRIVATE lux_consensus Threads::Threads)

add_test(NAME consensus_test COMMAND test_consensus)
