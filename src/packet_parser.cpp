#include "packet_parser.h"

#include <cstring>

namespace dpi {

namespace {
constexpr size_t ETH_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

inline uint16_t readU16BE(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t readU32BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
}  // namespace

bool PacketParser::parse(const uint8_t* data, size_t len, ParsedPacket& out) {
    out = ParsedPacket{};
    size_t offset = 0;

    if (!parseEthernet(data, len, out, offset)) return false;

    if (out.ethertype == ETHERTYPE_IPV4) {
        if (!parseIPv4(data, len, out, offset)) return false;

        if (out.protocol == L4Protocol::TCP) {
            parseTCP(data, len, out, offset);
        } else if (out.protocol == L4Protocol::UDP) {
            parseUDP(data, len, out, offset);
        } else {
            out.payload = data + offset;
            out.payload_len = len - offset;
        }
    }

    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset) {
    if (len < ETH_HEADER_LEN) return false;

    std::memcpy(out.dst_mac, data + 0, 6);
    std::memcpy(out.src_mac, data + 6, 6);
    out.ethertype = readU16BE(data + 12);

    offset = ETH_HEADER_LEN;
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset) {
    if (offset + 20 > len) return false;  // fixed minimum IPv4 header

    const uint8_t* ip = data + offset;

    uint8_t version = (ip[0] >> 4) & 0x0F;
    uint8_t ihl_words = ip[0] & 0x0F;  // header length in 32-bit words
    uint8_t header_len = static_cast<uint8_t>(ihl_words * 4);

    if (version != 4 || ihl_words < 5) return false;   // malformed per RFC 791
    if (offset + header_len > len) return false;        // options would run past buffer

    out.has_ip = true;
    out.ip_version = version;
    out.ip_header_len = header_len;
    out.ttl = ip[8];

    uint8_t proto = ip[9];
    out.protocol = (proto == 6) ? L4Protocol::TCP : (proto == 17) ? L4Protocol::UDP : L4Protocol::UNKNOWN;

    out.src_ip = readU32BE(ip + 12);
    out.dst_ip = readU32BE(ip + 16);

    offset += header_len;  // correctly skips any IP options, unlike a hardcoded +20
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset) {
    if (offset + 20 > len) return false;  // fixed minimum TCP header

    const uint8_t* tcp = data + offset;

    out.src_port = readU16BE(tcp + 0);
    out.dst_port = readU16BE(tcp + 2);
    out.tcp_seq = readU32BE(tcp + 4);
    out.tcp_ack = readU32BE(tcp + 8);

    uint8_t data_offset_words = (tcp[12] >> 4) & 0x0F;
    uint8_t header_len = static_cast<uint8_t>(data_offset_words * 4);

    if (data_offset_words < 5) return false;
    if (offset + header_len > len) return false;  // options would run past buffer

    out.tcp_flags = tcp[13];
    out.tcp_header_len = header_len;
    out.has_l4 = true;

    size_t payload_offset = offset + header_len;  // correctly skips TCP options
    out.payload = data + payload_offset;
    out.payload_len = len - payload_offset;

    offset = payload_offset;
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset) {
    if (offset + 8 > len) return false;

    const uint8_t* udp = data + offset;

    out.src_port = readU16BE(udp + 0);
    out.dst_port = readU16BE(udp + 2);
    uint16_t udp_len = readU16BE(udp + 4);  // includes the 8-byte UDP header itself

    out.has_l4 = true;

    size_t payload_offset = offset + 8;
    if (payload_offset > len) return false;

    // Prefer the UDP length field when it's self-consistent; fall back to
    // whatever's actually available for truncated/malformed captures rather
    // than reading past the buffer.
    size_t declared_payload_len = (udp_len >= 8) ? (udp_len - 8) : 0;
    size_t available = len - payload_offset;
    size_t payload_len = (declared_payload_len <= available) ? declared_payload_len : available;

    out.payload = data + payload_offset;
    out.payload_len = payload_len;

    offset = payload_offset + payload_len;
    return true;
}

}  // namespace dpi
