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
    src/main.cpp
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

# List your test source files here
set(TEST_SOURCES
    # Add more test files as needed
    test/test_main.cpp
    test/test_feature.cpp
    test/test_packet.cpp
    test/test_flow.cpp
)

# Include test files in build
include_directories(test)

# Enable testing
enable_testing()

# Create an executable and test for each test source file
foreach(test_src ${TEST_SOURCES})
    # Get the file name without directory
    get_filename_component(test_name ${test_src} NAME_WE)

    # Create an executable for this test
    add_executable(${test_name} ${test_src})

    # Link the libraries and gTest
    target_link_libraries(${test_name} ${LIBRARIES} gtest gtest_main)

    # Add the test target
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
