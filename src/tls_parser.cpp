#include "tls_parser.h"

namespace dpi {

namespace {
constexpr uint8_t TLS_CONTENT_TYPE_HANDSHAKE = 0x16;
constexpr uint8_t TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
constexpr uint16_t TLS_EXTENSION_SERVER_NAME = 0x0000;
constexpr uint8_t SNI_NAME_TYPE_HOST_NAME = 0x00;

inline uint16_t readU16BE(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
}  // namespace

TlsParseStatus tryExtractSni(const uint8_t* data, size_t len, std::string& sni_out) {
    // --- TLS record header: type(1) + version(2) + length(2) ---
    constexpr size_t RECORD_HEADER_LEN = 5;
    if (len < RECORD_HEADER_LEN) return TlsParseStatus::Incomplete;

    if (data[0] != TLS_CONTENT_TYPE_HANDSHAKE) return TlsParseStatus::NotTls;

    uint16_t record_len = readU16BE(data + 3);
    size_t record_end = RECORD_HEADER_LEN + record_len;
    if (len < record_end) return TlsParseStatus::Incomplete;  // body hasn't fully arrived yet

    // From here on the entire record is in hand, so any further
    // inconsistency means malformed data, not just "not arrived yet".
    const uint8_t* hs = data + RECORD_HEADER_LEN;
    size_t hs_len = record_len;

    constexpr size_t HANDSHAKE_HEADER_LEN = 4;  // type(1) + length(3)
    if (hs_len < HANDSHAKE_HEADER_LEN) return TlsParseStatus::Malformed;

    if (hs[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) return TlsParseStatus::NotTls;

    uint32_t handshake_len = (static_cast<uint32_t>(hs[1]) << 16) |
                              (static_cast<uint32_t>(hs[2]) << 8) | static_cast<uint32_t>(hs[3]);
    if (HANDSHAKE_HEADER_LEN + handshake_len > hs_len) return TlsParseStatus::Malformed;

    const uint8_t* ch = hs + HANDSHAKE_HEADER_LEN;
    size_t ch_len = handshake_len;
    size_t pos = 0;

    // client_version(2) + random(32)
    if (pos + 34 > ch_len) return TlsParseStatus::Malformed;
    pos += 34;

    // session_id: length(1) + session_id
    if (pos + 1 > ch_len) return TlsParseStatus::Malformed;
    uint8_t session_id_len = ch[pos];
    pos += 1;
    if (pos + session_id_len > ch_len) return TlsParseStatus::Malformed;
    pos += session_id_len;

    // cipher_suites: length(2) + cipher_suites
    if (pos + 2 > ch_len) return TlsParseStatus::Malformed;
    uint16_t cipher_suites_len = readU16BE(ch + pos);
    pos += 2;
    if (pos + cipher_suites_len > ch_len) return TlsParseStatus::Malformed;
    pos += cipher_suites_len;

    // compression_methods: length(1) + compression_methods
    if (pos + 1 > ch_len) return TlsParseStatus::Malformed;
    uint8_t comp_methods_len = ch[pos];
    pos += 1;
    if (pos + comp_methods_len > ch_len) return TlsParseStatus::Malformed;
    pos += comp_methods_len;

    // extensions are optional — a ClientHello with none simply ends here
    if (pos == ch_len) return TlsParseStatus::NoSni;
    if (pos + 2 > ch_len) return TlsParseStatus::Malformed;
    uint16_t extensions_len = readU16BE(ch + pos);
    pos += 2;
    if (pos + extensions_len > ch_len) return TlsParseStatus::Malformed;
    size_t extensions_end = pos + extensions_len;

    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = readU16BE(ch + pos);
        uint16_t ext_len = readU16BE(ch + pos + 2);
        pos += 4;

        if (pos + ext_len > extensions_end) return TlsParseStatus::Malformed;

        if (ext_type == TLS_EXTENSION_SERVER_NAME) {
            size_t sni_pos = pos;
            size_t sni_end = pos + ext_len;

            if (sni_pos + 2 > sni_end) return TlsParseStatus::Malformed;
            uint16_t list_len = readU16BE(ch + sni_pos);
            sni_pos += 2;
            if (sni_pos + list_len > sni_end) return TlsParseStatus::Malformed;
            size_t list_end = sni_pos + list_len;

            while (sni_pos + 3 <= list_end) {
                uint8_t name_type = ch[sni_pos];
                uint16_t name_len = readU16BE(ch + sni_pos + 1);
                sni_pos += 3;
                if (sni_pos + name_len > list_end) return TlsParseStatus::Malformed;

                if (name_type == SNI_NAME_TYPE_HOST_NAME) {
                    sni_out.assign(reinterpret_cast<const char*>(ch + sni_pos), name_len);
                    return TlsParseStatus::Found;
                }

                sni_pos += name_len;
            }
            return TlsParseStatus::NoSni;  // server_name extension present, no host_name entry
        }

        pos += ext_len;
    }

    return TlsParseStatus::NoSni;
}

}  // namespace dpi