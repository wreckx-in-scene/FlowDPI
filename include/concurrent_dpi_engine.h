#pragma once
#include <cstddef>
#include <string>

#include "block_rules.h"
#include "dpi_engine.h"

namespace dpi {

// Multi-threaded DPI engine: one reader/load-balancer thread parses
// packets and routes each to a fixed worker by hashing its five-tuple,
// so every packet of a given flow always lands on the same worker, in
// send order. That's what lets each worker own its flow table (and TCP
// reassembly state) with zero locking between workers — the tradeoff is
// no parallelism *within* a single very high-volume flow, only across
// flows.
//
// Architecture: reader (LB) -> N bounded per-worker queues -> N fast-path
// worker threads, each wrapping its own single-threaded DpiEngine. This
// mirrors the LB -> fast-path shard design from the project's original
// inspiration repo, but on a generic, independently-tested BoundedQueue
// rather than a bespoke queue, and with per-shard state instead of one
// shared flow table needing external locking. See NOTES.md for why
// mutex+condvar was chosen over a lock-free ring buffer here.
class ConcurrentDpiEngine {
public:
    ConcurrentDpiEngine(BlockRules rules, size_t num_workers, size_t queue_capacity = 1024);

    // Processes every packet in the given pcap file across all worker
    // threads, then merges their reports. Returns false if the file
    // couldn't be opened. Blocks until every worker has drained.
    bool processFile(const std::string& pcap_path);

    // Combined report across all worker shards. Only valid after
    // processFile() returns. Note: blocked_entries / observed_snis order
    // reflects per-shard processing order, not original capture order —
    // each individual flow's own events are still correctly ordered
    // (one flow is always handled by exactly one worker), but events
    // from different flows interleave differently than in the
    // single-threaded engine. Documented in NOTES.md.
    const EngineReport& report() const { return merged_report_; }

    std::string renderReport() const;

private:
    BlockRules rules_;
    size_t num_workers_;
    size_t queue_capacity_;
    EngineReport merged_report_;
};

}  // namespace dpi