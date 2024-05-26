cmake_minimum_required(VERSION 3.12)

project(cicflowmeter)

# Include FetchContent module
include(FetchContent)
include_directories(include)

# Download and add Google Test
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/release-1.11.0.tar.gz
)
FetchContent_MakeAvailable(googletest)

# Add your source files here
set(SOURCES
    src/pcap2csv.cpp
)

# Add your test source files here
set(TEST_SOURCES
    test/test_basic_packet_info.cpp
    test/test_flow_feature.cpp
    test/test_main.cpp
    # Add more test files as needed
)

# Add any additional libraries or dependencies here
set(LIBRARIES
    pcap
    # Add other libraries if needed
)

# Set the executable target for the main application
add_executable(pcap2csv ${SOURCES})

# Link any libraries or dependencies
target_link_libraries(pcap2csv ${LIBRARIES})

# Set the executable target for tests
add_executable(run_tests ${TEST_SOURCES})

# Link the same libraries and gTest to the test executable
target_link_libraries(run_tests ${LIBRARIES} gtest gtest_main)

# Include test files in build
include_directories(test)

# Enable testing
enable_testing()

# Add a test target
add_test(NAME pcap2csv_tests COMMAND run_tests)
