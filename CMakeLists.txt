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
)
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
)
target_link_libraries(dpi_tests PRIVATE dpi_core)
target_include_directories(dpi_tests PRIVATE tests include)

add_test(NAME dpi_tests COMMAND dpi_tests)
