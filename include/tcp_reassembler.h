#pragma once
#include <cstdint>
#include <map>
#include <vector>

namespace dpi {

// TCP sequence-number-aware comparison: true if `a` comes before `b` in
// the stream, accounting for 32-bit wraparound. Never use plain `<` on
// raw sequence numbers — this is the standard mod-2^32 comparison trick
// (cast the difference to signed 32-bit).
inline bool seqLessThan(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
}

// Reassembles one direction of one TCP stream from out-of-order /
// overlapping / duplicate segments into a contiguous byte stream.
//
// Scope note: this trims a segment against `next_seq_` (bytes already
// consumed) but does not merge overlaps *between* two still-pending
// out-of-order segments — that needs an interval tree for full generality
// and is out of scope for now. Handles the common case (some reordering,
// occasional retransmits) correctly; documented as a known simplification
// in NOTES.md.
class TcpStreamReassembler {
public:
    // Feed a segment. `seq` is the TCP sequence number of data[0].
    void addSegment(uint32_t seq, const uint8_t* data, size_t len);

    // Returns and consumes any newly-available contiguous bytes. May
    // return empty if the next bytes needed haven't arrived yet (a gap).
    std::vector<uint8_t> pullContiguous();

    // True once at least one segment has been seen, i.e. the stream's
    // starting sequence number is known.
    bool initialized() const { return initialized_; }

    // Bytes currently buffered but not yet contiguous (sitting after a
    // gap). Useful for bounding per-flow memory use later.
    size_t pendingBytes() const;

private:
    bool initialized_ = false;
    bool consumed_any_ = false;  // true once pullContiguous() has actually delivered bytes
    uint32_t next_seq_ = 0;      // next byte we expect — the read cursor
    std::map<uint32_t, std::vector<uint8_t>> pending_;
};

}  // namespace dpi