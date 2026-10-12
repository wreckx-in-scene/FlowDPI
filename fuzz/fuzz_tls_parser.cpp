// libFuzzer harness for tryExtractSni — the most structurally complex
// parser in the codebase (deepest TLV nesting: record -> handshake ->
// extensions -> server-name-list -> server-name entry), so it's the
// highest-value target for fuzzing.
//
// Build (requires clang, not part of the normal cmake/ninja build):
//   clang++ -std=c++17 -Iinclude -fsanitize=fuzzer,address,undefined \
//       src/tls_parser.cpp fuzz/fuzz_tls_parser.cpp -o fuzz_tls_parser
//   ./fuzz_tls_parser -max_total_time=60
//
// Any crash/hang libFuzzer finds gets saved to a crash-<hash> file in the
// working directory — feed that back in as a regression test fixture
// once fixed.

#include <cstdint>
#include <cstddef>
#include <string>

#include "tls_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string sni;
    dpi::tryExtractSni(data, size, sni);
    return 0;
}