#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>

namespace dpi {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;  // bytes of packet data saved in this file
    uint32_t orig_len;  // actual length of packet on the wire
};
#pragma pack(pop)

struct RawPacket {
    PcapPacketHeader header{};
    std::vector<uint8_t> data;
};

enum class L4Protocol : uint8_t {
    UNKNOWN = 0,
    TCP = 6,
    UDP = 17,
};

struct FiveTuple {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    L4Protocol protocol = L4Protocol::UNKNOWN;

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = std::hash<uint32_t>()(t.src_ip);
        h ^= std::hash<uint32_t>()(t.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(t.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(t.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>()(static_cast<uint8_t>(t.protocol)) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct ParsedPacket {
    // Ethernet
    uint8_t dst_mac[6] = {};
    uint8_t src_mac[6] = {};
    uint16_t ethertype = 0;

    // IPv4
    bool has_ip = false;
    uint8_t ip_version = 0;
    uint8_t ip_header_len = 0;  // bytes, walked via IHL, not assumed
    uint8_t ttl = 0;
    L4Protocol protocol = L4Protocol::UNKNOWN;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;

    // TCP/UDP
    bool has_l4 = false;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_header_len = 0;  // bytes, only valid when protocol == TCP
    uint8_t tcp_flags = 0;       // only valid when protocol == TCP
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;

    // Payload: points into the buffer passed to PacketParser::parse().
    // Caller must keep that buffer alive for as long as this is used.
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;

    FiveTuple tuple() const {
        FiveTuple t;
        t.src_ip = src_ip;
        t.dst_ip = dst_ip;
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.protocol = protocol;
        return t;
    }
};

}  // namespace dpi
