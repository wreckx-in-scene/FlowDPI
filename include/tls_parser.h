#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace dpi {

enum class TlsParseStatus {
    Incomplete,  // not enough bytes yet to tell either way — feed more and retry
    Found,       // SNI extracted successfully, see sni_out
    NoSni,       // a valid ClientHello, but no server_name extension present
    NotTls,      // doesn't look like a TLS Handshake/ClientHello at all
    Malformed,   // looked like TLS but a length field was internally inconsistent
};

// Attempts to extract the SNI (server name) from the start of a byte
// stream expected to be a TLS record carrying a ClientHello.
//
// `data`/`len` must be a *reassembled, contiguous* TCP stream starting at
// the first byte of the connection — this function does not handle
// out-of-order bytes itself; feed it output from TcpStreamReassembler.
//
// Every length field read from the input (record length, handshake
// length, session ID length, cipher suite list length, extension
// lengths, ...) is walked and bounds-checked before being trusted, same
// discipline as PacketParser. Once the full TLS record has arrived
// (checked up front against `len`), any further inconsistency is a real
// Malformed rather than Incomplete, since we know we're not just missing
// bytes anymore.
//
// Known limitation (documented, not silently glossed over): a ClientHello
// that itself spans multiple TLS records (rare, but legal per RFC 8446)
// is not reassembled at the record layer — only TCP-segment-level
// fragmentation is handled. Flagged in NOTES.md as a follow-up.
TlsParseStatus tryExtractSni(const uint8_t* data, size_t len, std::string& sni_out);

}  // namespace dpi