#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "block_rules.h"
#include "tcp_reassembler.h"
#include "types.h"

namespace dpi {

enum class SniAttemptStatus {
    Pending,   // still buffering, haven't resolved yet
    Found,
    NoSni,
    NotTls,
    Malformed,
    GaveUp,    // exceeded the buffering cap without resolving — see MAX_REASSEMBLY_BYTES
};

struct FlowState {
    FiveTuple tuple;
    TcpStreamReassembler reassembler;
    std::vector<uint8_t> sni_buffer;  // accumulated reassembled bytes, tried on each new chunk
    SniAttemptStatus sni_status = SniAttemptStatus::Pending;
    std::string sni;

    bool blocked = false;
    std::string block_reason;

    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
};

struct EngineReport {
    uint64_t total_packets = 0;
    uint64_t total_flows = 0;
    uint64_t blocked_flows = 0;
    uint64_t blocked_packets = 0;

    struct BlockedEntry {
        std::string description;  // "src:port -> dst:port (sni)"
        std::string reason;
    };
    std::vector<BlockedEntry> blocked_entries;  // first-seen order

    std::vector<std::string> observed_snis;  // allowed flows' SNIs, first-seen order
};

// Single-threaded DPI engine: reads a pcap file, reassembles TCP streams
// enough to extract TLS SNI, checks flows against block rules, and
// produces a summary report.
//
// Scope note: state is tracked per five-tuple, i.e. per *direction* of a
// connection (client->server and server->client land in separate
// FlowState entries, since FiveTuple preserves src/dst order). A real
// firewall correlates both directions under one conntrack-style entry;
// this is a known, documented simplification — see NOTES.md. It doesn't
// affect blocking correctness (SNI only ever appears client->server, and
// IP blocking checks both src and dst on every packet), but it does mean
// the report counts each direction as its own "flow".
class DpiEngine {
public:
    explicit DpiEngine(BlockRules rules);

    // Processes every packet in the given pcap file. Returns false if the
    // file couldn't be opened.
    bool processFile(const std::string& pcap_path);

    const EngineReport& report() const { return report_; }

    // Human-readable summary, suitable for printing to stdout.
    std::string renderReport() const;

private:
    void processPacket(const RawPacket& raw);
    void tryResolveSni(FlowState& flow);

    BlockRules rules_;
    std::unordered_map<FiveTuple, FlowState, FiveTupleHash> flows_;
    EngineReport report_;

    // A ClientHello legitimately fits in a single ~16KB TLS record; past
    // this we're either not looking at TLS or something's gone wrong —
    // stop buffering rather than growing unbounded on adversarial/weird
    // traffic.
    static constexpr size_t MAX_REASSEMBLY_BYTES = 65536;
};

}  // namespace dpi