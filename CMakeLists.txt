cmake_minimum_required(VERSION 3.12)

project(cicflowmeter)

# set the C++ standard to C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable("${PROJECT_NAME}" src/main.cpp)

find_package(PcapPlusPlus REQUIRED)

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
