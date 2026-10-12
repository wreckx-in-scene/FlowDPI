// The correctness bar for ConcurrentDpiEngine is simple to state: running
// N workers over a pcap should produce the same aggregate result as the
// single-threaded DpiEngine on the same file, just possibly in a
// different event order. These tests build a multi-flow pcap (some
// blocked by IP, some by SNI, some allowed) and check both engines agree
// on the counts — this is the test that would catch a sharding bug
// (e.g. two packets of one flow accidentally routed to different
// workers, breaking reassembly) far more reliably than eyeballing the
// hashing logic.

#include "concurrent_dpi_engine.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <vector>

#include "block_rules.h"
#include "dpi_engine.h"
#include "test_framework.h"
#include "types.h"

using namespace dpi;

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

std::vector<uint8_t> buildTcpFrame(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                    uint16_t dst_port, uint32_t seq,
                                    const std::vector<uint8_t>& payload) {
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
    appendU32BE(pkt, src_ip);
    appendU32BE(pkt, dst_ip);

    appendU16BE(pkt, src_port);
    appendU16BE(pkt, dst_port);
    appendU32BE(pkt, seq);
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

std::string makeTempPcapPath() {
    static int counter = 0;
    auto path = std::filesystem::temp_directory_path() /
                ("dpi_concurrent_test_" + std::to_string(counter++) + ".pcap");
    return path.string();
}

void writePcap(const std::string& path, const std::vector<std::vector<uint8_t>>& frames) {
    std::ofstream f(path, std::ios::binary);
    PcapGlobalHeader gh{};
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.snaplen = 65535;
    gh.network = 1;
    f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    for (const auto& frame : frames) {
        PcapPacketHeader ph{};
        ph.incl_len = static_cast<uint32_t>(frame.size());
        ph.orig_len = static_cast<uint32_t>(frame.size());
        f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        f.write(reinterpret_cast<const char*>(frame.data()), frame.size());
    }
}

// Builds a pcap with many distinct flows: a mix of IP-blocked, SNI-
// blocked, and allowed traffic, with each flow's ClientHello (where
// present) chopped into several small out-of-order-ish packets to
// actually exercise reassembly under sharding, not just single-packet
// flows.
std::string buildMultiFlowPcap(int num_flows) {
    std::vector<std::vector<uint8_t>> frames;

    for (int i = 0; i < num_flows; i++) {
        uint32_t client_ip = 0xC0A80100 + static_cast<uint32_t>(i % 250);
        uint16_t client_port = static_cast<uint16_t>(50000 + i);

        if (i % 3 == 0) {
            // IP-blocked flow — no TLS needed.
            uint32_t blocked_ip = 0x0A000001;
            std::vector<uint8_t> payload = {'x'};
            frames.push_back(buildTcpFrame(client_ip, blocked_ip, client_port, 8080, 1, payload));
        } else if (i % 3 == 1) {
            // SNI-blocked flow, split into chunks.
            auto record = buildClientHelloRecord("ads.blocked-" + std::to_string(i) + ".example.com");
            uint32_t server_ip = 0x08080808;
            uint32_t seq = 1;
            size_t offset = 0;
            constexpr size_t CHUNK = 13;
            while (offset < record.size()) {
                size_t n = std::min(CHUNK, record.size() - offset);
                std::vector<uint8_t> chunk(record.begin() + offset, record.begin() + offset + n);
                frames.push_back(
                    buildTcpFrame(client_ip, server_ip, client_port, 443, seq, chunk));
                seq += static_cast<uint32_t>(n);
                offset += n;
            }
        } else {
            // Allowed flow.
            auto record = buildClientHelloRecord("safe-" + std::to_string(i) + ".example.org");
            uint32_t server_ip = 0x08080809;
            frames.push_back(buildTcpFrame(client_ip, server_ip, client_port, 443, 1, record));
        }
    }

    std::string path = makeTempPcapPath();
    writePcap(path, frames);
    return path;
}

}  // namespace

TEST(concurrent_engine_matches_sequential_engine_aggregate_counts) {
    std::string path = buildMultiFlowPcap(30);

    BlockRules rules_seq;
    rules_seq.addBlockedIp(0x0A000001);
    rules_seq.addBlockedDomain("example.com");  // catches the "blocked-N.example.com" SNIs

    BlockRules rules_conc = rules_seq;  // independent copy, same rules

    DpiEngine sequential(rules_seq);
    CHECK(sequential.processFile(path));

    ConcurrentDpiEngine concurrent(rules_conc, /*num_workers=*/4);
    CHECK(concurrent.processFile(path));

    const auto& seq_rep = sequential.report();
    const auto& conc_rep = concurrent.report();

    CHECK_EQ(seq_rep.total_packets, conc_rep.total_packets);
    CHECK_EQ(seq_rep.total_flows, conc_rep.total_flows);
    CHECK_EQ(seq_rep.blocked_flows, conc_rep.blocked_flows);
    CHECK_EQ(seq_rep.blocked_packets, conc_rep.blocked_packets);

    // Order can differ (different shards finish in different orders), so
    // compare as sets rather than sequences.
    std::set<std::string> seq_snis(seq_rep.observed_snis.begin(), seq_rep.observed_snis.end());
    std::set<std::string> conc_snis(conc_rep.observed_snis.begin(), conc_rep.observed_snis.end());
    CHECK(seq_snis == conc_snis);

    std::remove(path.c_str());
}

TEST(concurrent_engine_with_single_worker_matches_multi_worker) {
    // Same input, 1 worker vs 8 workers — sharding shouldn't change the
    // outcome, only how work is distributed.
    std::string path = buildMultiFlowPcap(20);

    BlockRules rules1;
    rules1.addBlockedIp(0x0A000001);
    rules1.addBlockedDomain("example.com");
    BlockRules rules8 = rules1;

    ConcurrentDpiEngine one_worker(rules1, 1);
    CHECK(one_worker.processFile(path));

    ConcurrentDpiEngine eight_workers(rules8, 8);
    CHECK(eight_workers.processFile(path));

    CHECK_EQ(one_worker.report().total_flows, eight_workers.report().total_flows);
    CHECK_EQ(one_worker.report().blocked_flows, eight_workers.report().blocked_flows);
    CHECK_EQ(one_worker.report().total_packets, eight_workers.report().total_packets);

    std::remove(path.c_str());
}

TEST(concurrent_engine_reassembles_split_sni_correctly_under_sharding) {
    // Specifically targets the sharding hazard: if a flow's packets ever
    // landed on two different workers, reassembly would see a gap it can
    // never fill and the SNI would never resolve. Run enough distinct
    // flows across enough workers that if hashing were broken, this
    // would very likely surface as a missing SNI.
    std::string path = buildMultiFlowPcap(60);

    BlockRules rules;
    rules.addBlockedIp(0x0A000001);
    // No domain rule this time — just checking every SNI-bearing flow
    // actually resolved to *something*, blocked or not.

    ConcurrentDpiEngine engine(rules, 6);
    CHECK(engine.processFile(path));

    // 60 flows, 1/3 IP-blocked (no SNI attempted), 2/3 TLS (should all
    // resolve to Found given well-formed input) — so expect 40
    // observed SNIs (all allowed here, no domain rule blocking them).
    CHECK_EQ(engine.report().observed_snis.size(), 40u);

    std::remove(path.c_str());
}