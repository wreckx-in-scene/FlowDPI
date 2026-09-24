// These tests exercise the whole pipeline through the public API a real
// user of the tool would hit: write a synthetic pcap, hand it to
// DpiEngine, check the resulting report. This is the level that actually
// proves the milestone works, not just its individual pieces.

#include "dpi_engine.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include "block_rules.h"
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
    uint8_t dst_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
    pkt.insert(pkt.end(), src_mac, src_mac + 6);
    appendU16BE(pkt, 0x0800);

    size_t ip_start = pkt.size();
    pkt.push_back((4 << 4) | 5);
    pkt.push_back(0);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    pkt.push_back(64);
    pkt.push_back(6);  // TCP
    appendU16BE(pkt, 0);
    appendU32BE(pkt, src_ip);
    appendU32BE(pkt, dst_ip);

    appendU16BE(pkt, src_port);
    appendU16BE(pkt, dst_port);
    appendU32BE(pkt, seq);
    appendU32BE(pkt, 0);      // ack
    pkt.push_back(5 << 4);    // data offset = 5, no options
    pkt.push_back(0x18);      // PSH+ACK
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
                ("dpi_engine_test_" + std::to_string(counter++) + ".pcap");
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

}  // namespace

TEST(engine_blocks_flow_by_sni_split_across_packets) {
    uint32_t client_ip = 0xC0A80101;  // 192.168.1.1
    uint32_t server_ip = 0x08080808;  // 8.8.8.8
    uint16_t client_port = 55000;
    uint16_t server_port = 443;

    auto record = buildClientHelloRecord("blocked.example.com");

    // Split across several packets, each with the correct running seq —
    // this is the realistic path: the engine never sees the ClientHello
    // whole in any single captured packet.
    std::vector<std::vector<uint8_t>> frames;
    constexpr size_t CHUNK = 9;
    uint32_t seq = 1;
    size_t offset = 0;
    while (offset < record.size()) {
        size_t n = std::min(CHUNK, record.size() - offset);
        std::vector<uint8_t> chunk(record.begin() + offset, record.begin() + offset + n);
        frames.push_back(buildTcpFrame(client_ip, server_ip, client_port, server_port, seq, chunk));
        seq += static_cast<uint32_t>(n);
        offset += n;
    }

    std::string path = makeTempPcapPath();
    writePcap(path, frames);

    BlockRules rules;
    rules.addBlockedDomain("example.com");  // rule is the parent domain; SNI is a subdomain

    DpiEngine engine(rules);
    CHECK(engine.processFile(path));

    const auto& rep = engine.report();
    CHECK_EQ(rep.total_flows, 1u);
    CHECK_EQ(rep.blocked_flows, 1u);
    CHECK(!rep.blocked_entries.empty());

    std::remove(path.c_str());
}

TEST(engine_allows_flow_with_unblocked_sni) {
    uint32_t client_ip = 0xC0A80101;
    uint32_t server_ip = 0x08080808;

    auto record = buildClientHelloRecord("safe.example.org");
    std::vector<std::vector<uint8_t>> frames = {
        buildTcpFrame(client_ip, server_ip, 55001, 443, 1, record)};

    std::string path = makeTempPcapPath();
    writePcap(path, frames);

    BlockRules rules;
    rules.addBlockedDomain("example.com");  // .org, not .com — should not match

    DpiEngine engine(rules);
    CHECK(engine.processFile(path));

    const auto& rep = engine.report();
    CHECK_EQ(rep.blocked_flows, 0u);
    CHECK(!rep.observed_snis.empty());
    CHECK(rep.observed_snis[0] == "safe.example.org");

    std::remove(path.c_str());
}

TEST(engine_blocks_by_ip_without_needing_tls) {
    uint32_t client_ip = 0xC0A80101;
    uint32_t blocked_server_ip = 0x0A000001;  // 10.0.0.1

    std::vector<uint8_t> payload = {'x', 'y', 'z'};  // not TLS — IP block shouldn't care
    std::vector<std::vector<uint8_t>> frames = {
        buildTcpFrame(client_ip, blocked_server_ip, 55002, 8080, 1, payload)};

    std::string path = makeTempPcapPath();
    writePcap(path, frames);

    BlockRules rules;
    rules.addBlockedIp(blocked_server_ip);

    DpiEngine engine(rules);
    CHECK(engine.processFile(path));

    const auto& rep = engine.report();
    CHECK_EQ(rep.blocked_flows, 1u);

    std::remove(path.c_str());
}

TEST(engine_stops_inspecting_once_flow_is_blocked) {
    // After a flow is blocked, further packets on it should just be
    // counted as blocked, not re-run through parsing/SNI logic — flow-
    // level blocking, not per-packet re-evaluation.
    uint32_t client_ip = 0xC0A80101;
    uint32_t blocked_server_ip = 0x0A000001;

    std::vector<uint8_t> payload = {'a'};
    std::vector<std::vector<uint8_t>> frames = {
        buildTcpFrame(client_ip, blocked_server_ip, 55003, 8080, 1, payload),
        buildTcpFrame(client_ip, blocked_server_ip, 55003, 8080, 2, payload),
        buildTcpFrame(client_ip, blocked_server_ip, 55003, 8080, 3, payload),
    };

    std::string path = makeTempPcapPath();
    writePcap(path, frames);

    BlockRules rules;
    rules.addBlockedIp(blocked_server_ip);

    DpiEngine engine(rules);
    CHECK(engine.processFile(path));

    const auto& rep = engine.report();
    CHECK_EQ(rep.total_flows, 1u);       // still just one flow
    CHECK_EQ(rep.blocked_flows, 1u);     // blocked once, not three times
    CHECK_EQ(rep.blocked_packets, 3u);   // but every packet on it counted as blocked

    std::remove(path.c_str());
}