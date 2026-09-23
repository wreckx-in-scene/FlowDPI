#include "tls_parser.h"

#include <vector>

#include "test_framework.h"

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

// Builds a full TLS record containing a ClientHello. `hostname` is
// embedded as an SNI extension when non-empty; when empty, no
// server_name extension is added at all.
std::vector<uint8_t> buildClientHello(const std::string& hostname) {
    // --- Build the ClientHello body first (need its length up front) ---
    std::vector<uint8_t> ch;
    appendU16BE(ch, 0x0303);              // client_version: TLS 1.2
    ch.insert(ch.end(), 32, 0xAB);         // random (32 bytes, arbitrary)
    ch.push_back(0x00);                    // session_id_length = 0

    // cipher_suites: two arbitrary suites
    appendU16BE(ch, 4);
    appendU16BE(ch, 0x1301);
    appendU16BE(ch, 0x1302);

    // compression_methods: just "null"
    ch.push_back(1);
    ch.push_back(0x00);

    // extensions
    std::vector<uint8_t> extensions;
    if (!hostname.empty()) {
        std::vector<uint8_t> sni_ext;
        appendU16BE(sni_ext, static_cast<uint16_t>(3 + hostname.size()));  // server_name_list length
        sni_ext.push_back(0x00);                                          // name_type = host_name
        appendU16BE(sni_ext, static_cast<uint16_t>(hostname.size()));
        sni_ext.insert(sni_ext.end(), hostname.begin(), hostname.end());

        appendU16BE(extensions, 0x0000);  // extension type = server_name
        appendU16BE(extensions, static_cast<uint16_t>(sni_ext.size()));
        extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());
    }
    appendU16BE(ch, static_cast<uint16_t>(extensions.size()));
    ch.insert(ch.end(), extensions.begin(), extensions.end());

    // --- Handshake header wraps the ClientHello body ---
    std::vector<uint8_t> hs;
    hs.push_back(0x01);  // ClientHello
    appendU24BE(hs, static_cast<uint32_t>(ch.size()));
    hs.insert(hs.end(), ch.begin(), ch.end());

    // --- Record header wraps the handshake message ---
    std::vector<uint8_t> record;
    record.push_back(0x16);  // Handshake
    record.push_back(0x03);
    record.push_back(0x01);  // record version (often 3.1 regardless of client_version)
    appendU16BE(record, static_cast<uint16_t>(hs.size()));
    record.insert(record.end(), hs.begin(), hs.end());

    return record;
}

}  // namespace

TEST(extracts_sni_from_complete_client_hello) {
    auto pkt = buildClientHello("example.com");
    std::string sni;
    auto status = tryExtractSni(pkt.data(), pkt.size(), sni);
    CHECK(status == TlsParseStatus::Found);
    CHECK(sni == "example.com");
}

TEST(reports_no_sni_when_extension_absent) {
    auto pkt = buildClientHello("");  // no hostname -> no server_name extension
    std::string sni;
    auto status = tryExtractSni(pkt.data(), pkt.size(), sni);
    CHECK(status == TlsParseStatus::NoSni);
}

TEST(reports_incomplete_when_record_not_fully_arrived) {
    auto pkt = buildClientHello("example.com");
    // Only hand over the record header plus a few bytes — the parser must
    // recognize it doesn't have the whole record yet, not misparse a
    // truncated buffer as malformed or as a match.
    std::vector<uint8_t> partial(pkt.begin(), pkt.begin() + 10);
    std::string sni;
    auto status = tryExtractSni(partial.data(), partial.size(), sni);
    CHECK(status == TlsParseStatus::Incomplete);
}

TEST(reports_not_tls_for_non_handshake_content_type) {
    std::vector<uint8_t> pkt = {0x17, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5};  // 0x17 = Application Data
    std::string sni;
    auto status = tryExtractSni(pkt.data(), pkt.size(), sni);
    CHECK(status == TlsParseStatus::NotTls);
}

TEST(reports_malformed_on_inconsistent_length_field) {
    auto pkt = buildClientHello("example.com");
    // Corrupt the session_id_length byte (first byte of the ClientHello
    // body, right after record header (5) + handshake header (4) +
    // client_version(2) + random(32)) to claim more bytes than exist.
    size_t session_id_len_offset = 5 + 4 + 34;
    pkt[session_id_len_offset] = 0xFF;  // absurdly large session ID claim

    std::string sni;
    auto status = tryExtractSni(pkt.data(), pkt.size(), sni);
    CHECK(status == TlsParseStatus::Malformed);
}

TEST(handles_ip_and_tcp_options_free_client_hello_with_long_hostname) {
    // Sanity check with a longer, more realistic hostname.
    auto pkt = buildClientHello("api.streaming-service.example.co.uk");
    std::string sni;
    auto status = tryExtractSni(pkt.data(), pkt.size(), sni);
    CHECK(status == TlsParseStatus::Found);
    CHECK(sni == "api.streaming-service.example.co.uk");
}