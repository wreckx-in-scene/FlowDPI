// Dependency-free micro-benchmark. Deliberately not using a benchmarking
// library (Google Benchmark, etc.) — same reasoning as the hand-rolled
// test framework: this is small enough that a raw std::chrono loop is
// more transparent than a dependency, and every line is something you
// could explain in an interview.
//
// Reports latency *percentiles*, not just average throughput. A mean
// hides tail behavior — p99/p999 is what actually matters for
// something in a packet-processing hot path, since a rare slow path
// (e.g. hitting the TLS parser's Malformed branch after a deep walk)
// can dominate real-world behavior even if it's fast on average.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

#include "packet_parser.h"
#include "tls_parser.h"

using namespace dpi;
using Clock = std::chrono::steady_clock;

namespace {

void appendU16BE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}
void appendU24BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}
void appendU32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

std::vector<uint8_t> buildTcpFrame(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> pkt;
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    pkt.insert(pkt.end(), mac, mac + 6);
    pkt.insert(pkt.end(), mac, mac + 6);
    appendU16BE(pkt, 0x0800);

    size_t ip_start = pkt.size();
    pkt.push_back((4 << 4) | 5);
    pkt.push_back(0);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    pkt.push_back(64);
    pkt.push_back(6);
    appendU16BE(pkt, 0);
    appendU32BE(pkt, 0xC0A80101);
    appendU32BE(pkt, 0x08080808);

    appendU16BE(pkt, 55000);
    appendU16BE(pkt, 443);
    appendU32BE(pkt, 1);
    appendU32BE(pkt, 0);
    pkt.push_back(5 << 4);
    pkt.push_back(0x18);
    appendU16BE(pkt, 65535);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);

    pkt.insert(pkt.end(), payload.begin(), payload.end());

    uint16_t total_len = static_cast<uint16_t>(pkt.size() - ip_start);
    pkt[ip_start + 2] = static_cast<uint8_t>(total_len >> 8);
    pkt[ip_start + 3] = static_cast<uint8_t>(total_len & 0xFF);
    return pkt;
}

std::vector<uint8_t> buildClientHelloRecord(const std::string& hostname) {
    std::vector<uint8_t> ch;
    appendU16BE(ch, 0x0303);
    ch.insert(ch.end(), 32, 0xAB);
    ch.push_back(0x00);
    appendU16BE(ch, 4);
    appendU16BE(ch, 0x1301);
    appendU16BE(ch, 0x1302);
    ch.push_back(1);
    ch.push_back(0x00);

    std::vector<uint8_t> sni_ext;
    appendU16BE(sni_ext, static_cast<uint16_t>(3 + hostname.size()));
    sni_ext.push_back(0x00);
    appendU16BE(sni_ext, static_cast<uint16_t>(hostname.size()));
    sni_ext.insert(sni_ext.end(), hostname.begin(), hostname.end());

    std::vector<uint8_t> extensions;
    appendU16BE(extensions, 0x0000);
    appendU16BE(extensions, static_cast<uint16_t>(sni_ext.size()));
    extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());

    appendU16BE(ch, static_cast<uint16_t>(extensions.size()));
    ch.insert(ch.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01);
    appendU24BE(hs, static_cast<uint32_t>(ch.size()));
    hs.insert(hs.end(), ch.begin(), ch.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x01);
    appendU16BE(record, static_cast<uint16_t>(hs.size()));
    record.insert(record.end(), hs.begin(), hs.end());
    return record;
}

struct Stats {
    double p50, p90, p99, p999, max_ns;
    double throughput_per_sec;
};

Stats computeStats(std::vector<double>& latencies_ns, double total_seconds) {
    std::sort(latencies_ns.begin(), latencies_ns.end());
    auto pct = [&](double p) {
        size_t idx = static_cast<size_t>(p * static_cast<double>(latencies_ns.size() - 1));
        return latencies_ns[idx];
    };
    Stats s;
    s.p50 = pct(0.50);
    s.p90 = pct(0.90);
    s.p99 = pct(0.99);
    s.p999 = pct(0.999);
    s.max_ns = latencies_ns.back();
    s.throughput_per_sec = static_cast<double>(latencies_ns.size()) / total_seconds;
    return s;
}

void printStats(const std::string& label, const Stats& s) {
    std::cout << label << ":\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  p50:   " << s.p50 << " ns\n";
    std::cout << "  p90:   " << s.p90 << " ns\n";
    std::cout << "  p99:   " << s.p99 << " ns\n";
    std::cout << "  p999:  " << s.p999 << " ns\n";
    std::cout << "  max:   " << s.max_ns << " ns\n";
    std::cout << "  throughput: " << static_cast<uint64_t>(s.throughput_per_sec) << " ops/sec\n\n";
}

constexpr int ITERATIONS = 1'000'000;
constexpr int WARMUP = 10'000;

}  // namespace

int main() {
    // --- Benchmark 1: PacketParser on a plain TCP packet ---
    {
        std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        auto frame = buildTcpFrame(payload);

        ParsedPacket parsed;
        for (int i = 0; i < WARMUP; i++) PacketParser::parse(frame.data(), frame.size(), parsed);

        std::vector<double> latencies;
        latencies.reserve(ITERATIONS);
        auto bench_start = Clock::now();
        for (int i = 0; i < ITERATIONS; i++) {
            auto t0 = Clock::now();
            PacketParser::parse(frame.data(), frame.size(), parsed);
            auto t1 = Clock::now();
            latencies.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
        }
        double total_seconds = std::chrono::duration<double>(Clock::now() - bench_start).count();

        printStats("PacketParser::parse (Ethernet+IPv4+TCP, no options)",
                    computeStats(latencies, total_seconds));
    }

    // --- Benchmark 2: tryExtractSni on a complete, single-record ClientHello ---
    {
        auto record = buildClientHelloRecord("api.streaming-service.example.com");

        std::string sni;
        for (int i = 0; i < WARMUP; i++) tryExtractSni(record.data(), record.size(), sni);

        std::vector<double> latencies;
        latencies.reserve(ITERATIONS);
        auto bench_start = Clock::now();
        for (int i = 0; i < ITERATIONS; i++) {
            auto t0 = Clock::now();
            tryExtractSni(record.data(), record.size(), sni);
            auto t1 = Clock::now();
            latencies.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
        }
        double total_seconds = std::chrono::duration<double>(Clock::now() - bench_start).count();

        printStats("tryExtractSni (complete ClientHello, SNI found)",
                    computeStats(latencies, total_seconds));
    }

    return 0;
}