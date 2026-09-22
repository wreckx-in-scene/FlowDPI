#include "packet_parser.h"

#include <cstring>
#include <vector>

#include "test_framework.h"

using namespace dpi;

namespace {

void appendU16BE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void appendU32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

// Builds an Ethernet + IPv4 + TCP packet. ip_options_words / tcp_options_words
// let tests exercise header-length handling beyond the fixed 20-byte minimums
// — this is exactly the case a hardcoded-offset parser gets wrong.
std::vector<uint8_t> buildTcpPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                     uint16_t dst_port, const std::vector<uint8_t>& payload,
                                     uint8_t ip_options_words = 0, uint8_t tcp_options_words = 0) {
    std::vector<uint8_t> pkt;

    uint8_t dst_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    pkt.insert(pkt.end(), dst_mac, dst_mac + 6);
    pkt.insert(pkt.end(), src_mac, src_mac + 6);
    appendU16BE(pkt, 0x0800);  // IPv4

    size_t ip_header_start = pkt.size();
    uint8_t ihl_words = static_cast<uint8_t>(5 + ip_options_words);
    pkt.push_back(static_cast<uint8_t>((4 << 4) | ihl_words));
    pkt.push_back(0x00);
    appendU16BE(pkt, 0);  // total length, filled in below
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    pkt.push_back(64);
    pkt.push_back(6);  // TCP
    appendU16BE(pkt, 0);
    appendU32BE(pkt, src_ip);
    appendU32BE(pkt, dst_ip);
    for (int i = 0; i < ip_options_words; i++) appendU32BE(pkt, 0);

    uint8_t data_offset_words = static_cast<uint8_t>(5 + tcp_options_words);
    appendU16BE(pkt, src_port);
    appendU16BE(pkt, dst_port);
    appendU32BE(pkt, 1000);
    appendU32BE(pkt, 2000);
    pkt.push_back(static_cast<uint8_t>(data_offset_words << 4));
    pkt.push_back(0x18);  // PSH+ACK
    appendU16BE(pkt, 65535);
    appendU16BE(pkt, 0);
    appendU16BE(pkt, 0);
    for (int i = 0; i < tcp_options_words; i++) appendU32BE(pkt, 0x01010101);

    pkt.insert(pkt.end(), payload.begin(), payload.end());

    uint16_t total_len = static_cast<uint16_t>(pkt.size() - ip_header_start);
    pkt[ip_header_start + 2] = static_cast<uint8_t>(total_len >> 8);
    pkt[ip_header_start + 3] = static_cast<uint8_t>(total_len & 0xFF);

    return pkt;
}

}  // namespace

TEST(parses_basic_tcp_packet) {
    std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
    auto pkt = buildTcpPacket(0xC0A80101, 0x08080808, 54321, 443, payload);

    ParsedPacket parsed;
    bool ok = PacketParser::parse(pkt.data(), pkt.size(), parsed);

    CHECK(ok);
    CHECK(parsed.has_ip);
    CHECK(parsed.has_l4);
    CHECK_EQ(parsed.src_ip, 0xC0A80101u);
    CHECK_EQ(parsed.dst_ip, 0x08080808u);
    CHECK_EQ(parsed.src_port, 54321);
    CHECK_EQ(parsed.dst_port, 443);
    CHECK(parsed.protocol == L4Protocol::TCP);
    CHECK_EQ(parsed.payload_len, payload.size());
    CHECK(std::memcmp(parsed.payload, payload.data(), payload.size()) == 0);
}

TEST(skips_ip_options_correctly) {
    // The exact bug class the reference project had: hardcoding the IP
    // header as 20 bytes breaks the moment options are present, because
    // everything downstream gets misread.
    std::vector<uint8_t> payload = {'x'};
    auto pkt = buildTcpPacket(1, 2, 100, 200, payload, /*ip_options_words=*/2);

    ParsedPacket parsed;
    bool ok = PacketParser::parse(pkt.data(), pkt.size(), parsed);

    CHECK(ok);
    CHECK(parsed.has_l4);
    CHECK_EQ(parsed.src_port, 100);
    CHECK_EQ(parsed.dst_port, 200);
    CHECK_EQ(parsed.payload_len, payload.size());
}

TEST(skips_tcp_options_correctly) {
    std::vector<uint8_t> payload = {'y', 'y'};
    auto pkt = buildTcpPacket(1, 2, 100, 200, payload, 0, /*tcp_options_words=*/3);

    ParsedPacket parsed;
    bool ok = PacketParser::parse(pkt.data(), pkt.size(), parsed);

    CHECK(ok);
    CHECK_EQ(parsed.payload_len, payload.size());
    CHECK(std::memcmp(parsed.payload, payload.data(), payload.size()) == 0);
}

TEST(rejects_truncated_ethernet_header) {
    std::vector<uint8_t> too_short(10, 0);  // < 14 bytes
    ParsedPacket parsed;
    CHECK(!PacketParser::parse(too_short.data(), too_short.size(), parsed));
}

TEST(rejects_ip_header_claiming_more_than_buffer_has) {
    auto pkt = buildTcpPacket(1, 2, 100, 200, {});
    // Corrupt IHL to claim 15 words (60 bytes) of header, then truncate the
    // buffer so honoring that claim would read past the end. This is what
    // ASan would catch if the bounds check were missing.
    pkt[14] = (4 << 4) | 0x0F;
    pkt.resize(20);

    ParsedPacket parsed;
    CHECK(!PacketParser::parse(pkt.data(), pkt.size(), parsed));
}

TEST(handles_udp_packet) {
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
    pkt.push_back(17);  // UDP
    appendU16BE(pkt, 0);
    appendU32BE(pkt, 1);
    appendU32BE(pkt, 2);

    std::vector<uint8_t> payload = {'d', 'n', 's'};
    appendU16BE(pkt, 53);
    appendU16BE(pkt, 5353);
    appendU16BE(pkt, static_cast<uint16_t>(8 + payload.size()));
    appendU16BE(pkt, 0);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    uint16_t total_len = static_cast<uint16_t>(pkt.size() - ip_start);
    pkt[ip_start + 2] = static_cast<uint8_t>(total_len >> 8);
    pkt[ip_start + 3] = static_cast<uint8_t>(total_len & 0xFF);

    ParsedPacket parsed;
    bool ok = PacketParser::parse(pkt.data(), pkt.size(), parsed);

    CHECK(ok);
    CHECK(parsed.has_l4);
    CHECK(parsed.protocol == L4Protocol::UDP);
    CHECK_EQ(parsed.src_port, 53);
    CHECK_EQ(parsed.dst_port, 5353);
    CHECK_EQ(parsed.payload_len, payload.size());
}

TEST(five_tuple_equality_and_hash_agree) {
    FiveTuple a{0x01020304, 0x05060708, 1111, 443, L4Protocol::TCP};
    FiveTuple b{0x01020304, 0x05060708, 1111, 443, L4Protocol::TCP};
    FiveTuple c{0x01020304, 0x05060708, 1111, 80, L4Protocol::TCP};

    CHECK(a == b);
    CHECK(!(a == c));

    FiveTupleHash hasher;
    CHECK_EQ(hasher(a), hasher(b));
}
