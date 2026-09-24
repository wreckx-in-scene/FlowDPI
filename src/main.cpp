#include <cstdio>
#include <iostream>
#include <string>

#include "block_rules.h"
#include "dpi_engine.h"

namespace {
bool parseIpv4(const std::string& s, uint32_t& out) {
    unsigned a, b, c, d;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <pcap-file> [--block-ip <ip>]... [--block-domain <domain>]...\n";
        return 1;
    }

    std::string pcap_path = argv[1];
    dpi::BlockRules rules;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            uint32_t ip;
            if (parseIpv4(argv[++i], ip)) {
                rules.addBlockedIp(ip);
            } else {
                std::cerr << "Invalid IP, skipping: " << argv[i] << "\n";
            }
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.addBlockedDomain(argv[++i]);
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    dpi::DpiEngine engine(std::move(rules));
    if (!engine.processFile(pcap_path)) {
        std::cerr << "Failed to open pcap file: " << pcap_path << "\n";
        return 1;
    }

    std::cout << engine.renderReport();
    return 0;
}