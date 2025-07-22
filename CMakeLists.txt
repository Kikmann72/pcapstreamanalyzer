cmake_minimum_required(VERSION 3.2)    
project(pcapmcastanalyzer CXX)

set(CMAKE_CXX_STANDARD 11)

add_executable(pcapmcastanalyzer src/pcapmcastanalyzer.cpp)
target_compile_options(pcapmcastanalyzer PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(pcapmcastanalyzer pcap)

install(TARGETS pcapmcastanalyzer DESTINATION bin/)

enable_testing()

