// This is the test that matters most for this milestone: it proves the
// exact scenario the original inspiration repo couldn't handle — a TLS
// ClientHello whose bytes arrive across multiple TCP segments. A parser
// that reads straight from a single packet's payload (as the original
// did) would simply fail to find the SNI here, because it's never fully
// present in any one segment.

#include "tcp_reassembler.h"
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

std::vector<uint8_t> buildClientHello(const std::string& hostname) {
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

}  // namespace

TEST(reassembled_stream_extracts_sni_split_across_many_small_segments) {
    auto full_record = buildClientHello("split-across-segments.example.com");

    // Chop the ClientHello into small, arbitrary chunks — deliberately
    // not aligned to any TLS structure boundary (a byte can split right
    // in the middle of the hostname, a length field, anything), to prove
    // the reassembler doesn't care about TLS structure, only byte order.
    constexpr size_t CHUNK_SIZE = 7;

    TcpStreamReassembler reassembler;
    uint32_t seq = 1000;
    size_t offset = 0;
    while (offset < full_record.size()) {
        size_t n = std::min(CHUNK_SIZE, full_record.size() - offset);
        reassembler.addSegment(seq, full_record.data() + offset, n);
        seq += static_cast<uint32_t>(n);
        offset += n;
    }

    auto stream = reassembler.pullContiguous();
    CHECK(stream == full_record);

    std::string sni;
    auto status = tryExtractSni(stream.data(), stream.size(), sni);
    CHECK(status == TlsParseStatus::Found);
    CHECK(sni == "split-across-segments.example.com");
}

TEST(out_of_order_segments_still_extract_sni_once_reassembled) {
    auto full_record = buildClientHello("reordered.example.com");

    constexpr size_t CHUNK_SIZE = 11;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> chunks;
    uint32_t seq = 5000;
    size_t offset = 0;
    while (offset < full_record.size()) {
        size_t n = std::min(CHUNK_SIZE, full_record.size() - offset);
        chunks.emplace_back(seq, std::vector<uint8_t>(full_record.begin() + offset,
                                                        full_record.begin() + offset + n));
        seq += static_cast<uint32_t>(n);
        offset += n;
    }

    // Feed every other chunk first, then backfill — simulates real
    // network reordering rather than assuming segments always arrive
    // in send order.
    TcpStreamReassembler reassembler;
    for (size_t i = 0; i < chunks.size(); i += 2) {
        reassembler.addSegment(chunks[i].first, chunks[i].second.data(), chunks[i].second.size());
    }
    for (size_t i = 1; i < chunks.size(); i += 2) {
        reassembler.addSegment(chunks[i].first, chunks[i].second.data(), chunks[i].second.size());
    }

    auto stream = reassembler.pullContiguous();
    CHECK(stream == full_record);

    std::string sni;
    auto status = tryExtractSni(stream.data(), stream.size(), sni);
    CHECK(status == TlsParseStatus::Found);
    CHECK(sni == "reordered.example.com");
}