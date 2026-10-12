#include "concurrent_dpi_engine.h"

#include <memory>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#include "bounded_queue.h"
#include "packet_parser.h"
#include "pcap_reader.h"

namespace dpi {

namespace {

// One packet, already parsed, handed from the LB thread to a worker.
// Move-only (inherits that from RawPacket) — see types.h for why: the
// ParsedPacket::payload pointer inside `parsed` points into `raw`'s
// buffer, and only stays valid if `raw` is moved end-to-end, never
// copied. This struct's default move ctor/assign do exactly that
// (member-wise move), which is why it's safe to push through
// BoundedQueue's move-based push/pop.
struct WorkItem {
    RawPacket raw;
    ParsedPacket parsed;

    WorkItem() = default;
    WorkItem(const WorkItem&) = delete;
    WorkItem& operator=(const WorkItem&) = delete;
    WorkItem(WorkItem&&) = default;
    WorkItem& operator=(WorkItem&&) = default;
};

void mergeReportInto(EngineReport& dst, const EngineReport& src) {
    dst.total_packets += src.total_packets;
    dst.total_flows += src.total_flows;
    dst.blocked_flows += src.blocked_flows;
    dst.blocked_packets += src.blocked_packets;
    dst.blocked_entries.insert(dst.blocked_entries.end(), src.blocked_entries.begin(),
                                src.blocked_entries.end());
    dst.observed_snis.insert(dst.observed_snis.end(), src.observed_snis.begin(),
                              src.observed_snis.end());
    dst.packet_latencies_ns.insert(dst.packet_latencies_ns.end(), src.packet_latencies_ns.begin(),
                                    src.packet_latencies_ns.end());
}

}  // namespace

ConcurrentDpiEngine::ConcurrentDpiEngine(BlockRules rules, size_t num_workers, size_t queue_capacity)
    : rules_(std::move(rules)),
      num_workers_(num_workers > 0 ? num_workers : 1),
      queue_capacity_(queue_capacity > 0 ? queue_capacity : 1) {}

bool ConcurrentDpiEngine::processFile(const std::string& pcap_path) {
    PcapReader reader;
    if (!reader.open(pcap_path)) return false;

    // BoundedQueue holds a std::mutex, so it isn't movable — hold them by
    // unique_ptr rather than by value so growing/populating this vector
    // doesn't need to move a queue itself.
    std::vector<std::unique_ptr<BoundedQueue<WorkItem>>> queues;
    queues.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; i++) {
        queues.push_back(std::make_unique<BoundedQueue<WorkItem>>(queue_capacity_));
    }

    std::vector<DpiEngine> shard_engines;
    shard_engines.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; i++) shard_engines.emplace_back(rules_);

    // Fast-path workers: each drains exactly one queue into its own
    // DpiEngine. No cross-worker synchronization needed — the LB thread
    // guarantees a given flow's packets only ever land in one queue.
    std::vector<std::thread> workers;
    workers.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; i++) {
        workers.emplace_back([&queues, &shard_engines, i] {
            WorkItem item;
            while (queues[i]->pop(item)) {
                shard_engines[i].processParsedPacket(std::move(item.raw), item.parsed);
            }
        });
    }

    // Load balancer: read + parse on this thread, route by five-tuple
    // hash so a flow always lands on the same worker (preserving the
    // sequence order that reassembly depends on).
    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        ParsedPacket parsed;
        if (!PacketParser::parse(raw, parsed) || !parsed.has_ip) continue;

        size_t shard = FiveTupleHash{}(parsed.tuple()) % num_workers_;
        WorkItem item;
        item.raw = std::move(raw);
        item.parsed = parsed;
        if (!queues[shard]->push(std::move(item))) break;  // queue closed (shouldn't happen mid-run)
    }

    for (auto& q : queues) q->close();
    for (auto& w : workers) w.join();

    merged_report_ = EngineReport{};
    for (const auto& engine : shard_engines) mergeReportInto(merged_report_, engine.report());

    return true;
}

std::string ConcurrentDpiEngine::renderReport() const {
    std::ostringstream out;
    out << "=== FlowDPI Report (" << num_workers_ << " workers) ===\n";
    out << "Total packets:   " << merged_report_.total_packets << "\n";
    out << "Total flows:     " << merged_report_.total_flows << "\n";
    out << "Rule-matched flows:   " << merged_report_.blocked_flows << "\n";
    out << "Rule-matched packets: " << merged_report_.blocked_packets << "\n";

    if (!merged_report_.blocked_entries.empty()) {
        out << "\n-- Rule matches --\n";
        for (const auto& e : merged_report_.blocked_entries) {
            out << "  " << e.description << "  [" << e.reason << "]\n";
        }
    }

    if (!merged_report_.observed_snis.empty()) {
        out << "\n-- Observed SNIs (allowed) --\n";
        for (const auto& s : merged_report_.observed_snis) {
            out << "  " << s << "\n";
        }
    }

    if (!merged_report_.packet_latencies_ns.empty()) {
        auto lat = computeLatencyPercentiles(merged_report_.packet_latencies_ns);
        out << "\n-- Processing latency (per packet, excludes pcap I/O) --\n";
        out << "  p50:  " << lat.p50 << " ns\n";
        out << "  p99:  " << lat.p99 << " ns\n";
        out << "  p999: " << lat.p999 << " ns\n";
        out << "  max:  " << lat.max_ns << " ns\n";
    }

    return out.str();
}

}  // namespace dpi