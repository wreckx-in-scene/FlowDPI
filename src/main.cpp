#include <csignal>
#include <charconv>
#include <cstdio>
#include <iostream>
#include <string>

#include "block_rules.h"
#include "concurrent_dpi_engine.h"
#include "dpi_engine.h"

#ifdef DPI_HAVE_LIBPCAP
#include "live_capture.h"
#include "packet_parser.h"
#endif

namespace {
bool parseIpv4(const std::string& s, uint32_t& out) {
    unsigned a, b, c, d;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

bool parsePort(const std::string& s, uint16_t& out) {
    unsigned value = 0;
    const char* begin = s.data();
    const char* end = begin + s.size();
    auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{} || result.ptr != end || value > 65535) return false;
    out = static_cast<uint16_t>(value);
    return true;
}

void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " <pcap-file> [--block-ip <ip>]... [--block-domain <domain>]... "
                 "[--block-port <tcp|udp> <port>]... "
                 "[--workers <n>]\n";
#ifdef DPI_HAVE_LIBPCAP
    std::cerr << "   or: " << argv0
              << " --live <interface> [--block-ip <ip>]... [--block-domain <domain>]... "
                 "[--block-port <tcp|udp> <port>]...\n";
#endif
}

#ifdef DPI_HAVE_LIBPCAP
dpi::LiveCapture* g_capture = nullptr;  // for the signal handler — see note below

// Signal handlers can only call async-signal-safe functions and can't
// carry lambda captures, hence the plain global pointer + free function
// rather than anything fancier.
void handleSigint(int) {
    if (g_capture) g_capture->stop();
}
#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string target = argv[1];  // pcap path, or "--live" itself
    bool live_mode = (target == "--live");
    std::string live_interface;
    int arg_start = 2;

    if (live_mode) {
#ifndef DPI_HAVE_LIBPCAP
        std::cerr << "This build was compiled without libpcap — live capture isn't available. "
                     "Use a pcap file instead.\n";
        return 1;
#else
        if (argc < 3) {
            printUsage(argv[0]);
            return 1;
        }
        live_interface = argv[2];
        arg_start = 3;
#endif
    }

    dpi::BlockRules rules;
    size_t num_workers = 1;  // default: sequential DpiEngine, no threading overhead

    for (int i = arg_start; i < argc; i++) {
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
        } else if (arg == "--block-port" && i + 2 < argc) {
            std::string protocol = argv[++i];
            uint16_t port;
            if (!parsePort(argv[++i], port)) {
                std::cerr << "Invalid port, skipping: " << argv[i] << "\n";
            } else if (protocol == "tcp") {
                rules.addBlockedPort(dpi::L4Protocol::TCP, port);
            } else if (protocol == "udp") {
                rules.addBlockedPort(dpi::L4Protocol::UDP, port);
            } else {
                std::cerr << "Invalid transport protocol (use tcp or udp): " << protocol << "\n";
            }
        } else if (arg == "--workers" && i + 1 < argc) {
            num_workers = static_cast<size_t>(std::stoul(argv[++i]));
            if (num_workers == 0) num_workers = 1;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    if (live_mode) {
#ifdef DPI_HAVE_LIBPCAP
        dpi::LiveCapture capture;
        std::string err;
        if (!capture.open(live_interface, err)) {
            std::cerr << "Failed to open interface '" << live_interface << "': " << err << "\n";
            return 1;
        }

        g_capture = &capture;
        std::signal(SIGINT, handleSigint);
        std::cerr << "Capturing on " << live_interface << " — Ctrl+C to stop and print the report.\n";

        dpi::DpiEngine engine(std::move(rules));
        capture.loop([&engine](const uint8_t* data, size_t len) {
            dpi::RawPacket raw;
            raw.data.assign(data, data + len);
            dpi::ParsedPacket parsed;
            if (dpi::PacketParser::parse(raw, parsed)) {
                engine.processParsedPacket(std::move(raw), parsed);
            }
        });

        std::cout << engine.renderReport();
        return 0;
#endif
    }

    if (num_workers > 1) {
        dpi::ConcurrentDpiEngine engine(std::move(rules), num_workers);
        if (!engine.processFile(target)) {
            std::cerr << "Failed to open pcap file: " << target << "\n";
            return 1;
        }
        std::cout << engine.renderReport();
    } else {
        dpi::DpiEngine engine(std::move(rules));
        if (!engine.processFile(target)) {
            std::cerr << "Failed to open pcap file: " << target << "\n";
            return 1;
        }
        std::cout << engine.renderReport();
    }

    return 0;
}