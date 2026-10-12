cmake_minimum_required(VERSION 3.16)
project(dpi_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_SANITIZERS "Build with ASan + UBSan" ON)

add_library(dpi_core
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/tcp_reassembler.cpp
    src/tls_parser.cpp
    src/block_rules.cpp
    src/dpi_engine.cpp
    src/concurrent_dpi_engine.cpp
)
find_package(Threads REQUIRED)
target_link_libraries(dpi_core PUBLIC Threads::Threads)

# Packet capture is optional; offline PCAP analysis remains available without it.
if(WIN32)
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap/pcap.h
        HINTS "$ENV{NPCAP_SDK}/Include" "C:/WpdPack/Include"
              "C:/Npcap-SDK/Include" "C:/NpcapSDK/Include")
    find_library(PCAP_LIBRARY
        NAMES wpcap
        HINTS "$ENV{NPCAP_SDK}/Lib/x64" "C:/WpdPack/Lib/x64"
              "C:/Npcap-SDK/Lib/x64" "C:/NpcapSDK/Lib/x64")
    find_library(PACKET_LIBRARY
        NAMES Packet
        HINTS "$ENV{NPCAP_SDK}/Lib/x64" "C:/WpdPack/Lib/x64"
              "C:/Npcap-SDK/Lib/x64" "C:/NpcapSDK/Lib/x64")
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY AND PACKET_LIBRARY)
        message(STATUS "Npcap SDK found — live capture support enabled")
        target_sources(dpi_core PRIVATE src/live_capture.cpp)
        target_include_directories(dpi_core PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(dpi_core PUBLIC ${PCAP_LIBRARY} ${PACKET_LIBRARY} ws2_32)
        target_compile_definitions(dpi_core PUBLIC DPI_HAVE_LIBPCAP)
    else()
        message(STATUS "Npcap SDK not found — live capture disabled (pcap file replay still works)")
    endif()
else()
    find_library(PCAP_LIBRARY pcap)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
        message(STATUS "libpcap found — live capture support enabled")
        target_sources(dpi_core PRIVATE src/live_capture.cpp)
        target_include_directories(dpi_core PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(dpi_core PUBLIC ${PCAP_LIBRARY})
        target_compile_definitions(dpi_core PUBLIC DPI_HAVE_LIBPCAP)
    else()
        message(STATUS "libpcap not found — live capture disabled (pcap file replay still works)")
    endif()
endif()
target_include_directories(dpi_core PUBLIC include)
target_compile_options(dpi_core PUBLIC -Wall -Wextra)

if(ENABLE_SANITIZERS)
    target_compile_options(dpi_core PUBLIC -fsanitize=address,undefined -g -fno-omit-frame-pointer)
    target_link_options(dpi_core PUBLIC -fsanitize=address,undefined)
endif()

enable_testing()
add_executable(dpi_tests
    tests/main.cpp
    tests/test_pcap_reader.cpp
    tests/test_packet_parser.cpp
    tests/test_tcp_reassembler.cpp
    tests/test_tls_parser.cpp
    tests/test_reassembly_tls_integration.cpp
    tests/test_block_rules.cpp
    tests/test_dpi_engine.cpp
    tests/test_bounded_queue.cpp
    tests/test_concurrent_dpi_engine.cpp
)
target_link_libraries(dpi_tests PRIVATE dpi_core)
target_include_directories(dpi_tests PRIVATE tests include)

add_test(NAME dpi_tests COMMAND dpi_tests)

add_executable(flowdpi src/main.cpp)
target_link_libraries(flowdpi PRIVATE dpi_core)

add_executable(flowdpi_bench src/benchmark.cpp)
target_link_libraries(flowdpi_bench PRIVATE dpi_core)