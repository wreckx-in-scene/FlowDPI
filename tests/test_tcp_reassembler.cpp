#include "tcp_reassembler.h"

#include <vector>

#include "test_framework.h"

using namespace dpi;

namespace {
std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}
}  // namespace

TEST(reassembles_in_order_segments) {
    TcpStreamReassembler r;
    auto a = bytes("hello ");
    auto b = bytes("world");

    r.addSegment(1000, a.data(), a.size());
    auto out1 = r.pullContiguous();
    CHECK(out1 == a);

    r.addSegment(1000 + static_cast<uint32_t>(a.size()), b.data(), b.size());
    auto out2 = r.pullContiguous();
    CHECK(out2 == b);
}

TEST(buffers_out_of_order_segment_until_gap_fills) {
    TcpStreamReassembler r;
    auto first = bytes("AAAA");
    auto second = bytes("BBBB");

    uint32_t base = 5000;
    // second segment arrives first
    r.addSegment(base + static_cast<uint32_t>(first.size()), second.data(), second.size());

    // Reassembler hasn't seen the start of the stream yet, so nothing is
    // contiguous — but note: without a first addSegment, initialized_
    // would be set from *this* segment's seq, which is wrong for this
    // test's intent. Feed the first segment next, as real capture would.
    r.addSegment(base, first.data(), first.size());

    auto out = r.pullContiguous();
    std::vector<uint8_t> expected;
    expected.insert(expected.end(), first.begin(), first.end());
    expected.insert(expected.end(), second.begin(), second.end());
    CHECK(out == expected);
}

TEST(true_out_of_order_arrival_waits_for_gap) {
    // This time the reassembler is initialized by the *first* segment
    // seen (base), matching real capture order, and a later segment
    // arrives before the one that fills the gap between them.
    TcpStreamReassembler r;
    uint32_t base = 9000;
    auto seg0 = bytes("0000");
    auto seg2 = bytes("2222");
    auto seg1 = bytes("1111");

    r.addSegment(base, seg0.data(), seg0.size());                         // seq 9000
    r.addSegment(base + 8, seg2.data(), seg2.size());                     // seq 9008 — arrives early, out of order
    auto out1 = r.pullContiguous();
    CHECK(out1 == seg0);  // only the contiguous part so far; seg2 is stuck behind a gap

    r.addSegment(base + 4, seg1.data(), seg1.size());                     // seq 9004 — fills the gap
    auto out2 = r.pullContiguous();
    std::vector<uint8_t> expected;
    expected.insert(expected.end(), seg1.begin(), seg1.end());
    expected.insert(expected.end(), seg2.begin(), seg2.end());
    CHECK(out2 == expected);
}

TEST(drops_pure_retransmit_of_already_consumed_data) {
    TcpStreamReassembler r;
    auto a = bytes("hello");
    r.addSegment(100, a.data(), a.size());
    r.pullContiguous();

    // Exact retransmit of the same bytes at the same seq — should not
    // reappear or corrupt the stream.
    r.addSegment(100, a.data(), a.size());
    auto out = r.pullContiguous();
    CHECK(out.empty());
}

TEST(trims_partial_overlap_with_consumed_data) {
    TcpStreamReassembler r;
    auto a = bytes("hello");
    r.addSegment(100, a.data(), a.size());
    r.pullContiguous();

    // Overlapping retransmit: starts inside already-consumed range but
    // carries new bytes at the end.
    auto overlap = bytes("llo world");  // "llo" overlaps, " world" is new
    r.addSegment(102, overlap.data(), overlap.size());  // seq 102 = the 'l' in "hello"
    auto out = r.pullContiguous();
    CHECK(out == bytes(" world"));
}

TEST(handles_sequence_number_wraparound) {
    // Segment straddling the 32-bit sequence number wraparound point.
    // A naive `<` comparison on raw seq numbers would misorder this.
    TcpStreamReassembler r;
    uint32_t near_max = 0xFFFFFFF0;  // 16 bytes from wraparound
    auto seg_before = bytes("0123456789ABCDEF");  // 16 bytes, ends exactly at wraparound
    auto seg_after = bytes("wrapped");             // continues from seq 0

    r.addSegment(near_max, seg_before.data(), seg_before.size());
    auto out1 = r.pullContiguous();
    CHECK(out1 == seg_before);

    r.addSegment(0, seg_after.data(), seg_after.size());  // wrapped around to 0
    auto out2 = r.pullContiguous();
    CHECK(out2 == seg_after);
}

TEST(pending_bytes_reflects_buffered_gap_data) {
    TcpStreamReassembler r;
    auto seg0 = bytes("AAAA");
    auto seg2 = bytes("CCCC");
    r.addSegment(0, seg0.data(), seg0.size());
    r.pullContiguous();

    r.addSegment(8, seg2.data(), seg2.size());  // gap at seq 4-7, seg2 stuck pending
    CHECK_EQ(r.pendingBytes(), seg2.size());
}