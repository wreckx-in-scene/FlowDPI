#pragma once
#include "types.h"

namespace dpi {

// Parses raw captured bytes into structured fields.
//
// Every header length (IPv4 IHL, TCP data offset) is *read from the
// packet and walked*, never assumed to be the fixed minimum. That's the
// difference between handling real-world traffic (which routinely
// includes IP/TCP options) and only handling hand-picked demo packets.
// Every offset is bounds-checked against the actual buffer length before
// it's dereferenced.
class PacketParser {
public:
    static bool parse(const uint8_t* data, size_t len, ParsedPacket& out);

    static bool parse(const RawPacket& raw, ParsedPacket& out) {
        return parse(raw.data.data(), raw.data.size(), out);
    }

private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& out, size_t& offset);
};

}  // namespace dpi
