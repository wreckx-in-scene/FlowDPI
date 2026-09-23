#include "tcp_reassembler.h"

namespace dpi {

void TcpStreamReassembler::addSegment(uint32_t seq, const uint8_t* data, size_t len) {
    if (len == 0) return;

    if (!initialized_) {
        next_seq_ = seq;
        initialized_ = true;
    } else if (!consumed_any_ && seqLessThan(seq, next_seq_)) {
        // Nothing has been delivered to the caller yet, so our current
        // next_seq_ is only a guess based on whichever segment happened
        // to arrive first — it was never confirmed as the true stream
        // start. An earlier segment arriving now means that guess was
        // wrong, not that this is a stale retransmit. Widen the window
        // backwards. Once consumed_any_ is true, next_seq_ is a real
        // cursor and this no longer applies — an earlier segment past
        // that point genuinely is old data.
        next_seq_ = seq;
    }

    uint32_t seg_end = seq + static_cast<uint32_t>(len);  // exclusive, wraps like seq

    // Fully old data (a retransmit of bytes we've already consumed past) — drop.
    if (!seqLessThan(next_seq_, seg_end)) {
        return;
    }

    // Partial overlap with already-consumed bytes: trim the front so we
    // only buffer the genuinely new tail.
    if (seqLessThan(seq, next_seq_)) {
        uint32_t trim = next_seq_ - seq;
        data += trim;
        len -= trim;
        seq = next_seq_;
    }

    pending_[seq] = std::vector<uint8_t>(data, data + len);
}

std::vector<uint8_t> TcpStreamReassembler::pullContiguous() {
    std::vector<uint8_t> result;

    auto it = pending_.begin();
    while (it != pending_.end()) {
        uint32_t seg_seq = it->first;

        if (seqLessThan(next_seq_, seg_seq)) {
            break;  // gap — the next segment starts after our read cursor
        }

        auto& buf = it->second;
        if (seqLessThan(seg_seq, next_seq_)) {
            // Stale overlap (can happen if next_seq_ advanced since this
            // entry was inserted) — trim defensively before consuming.
            uint32_t trim = next_seq_ - seg_seq;
            if (trim >= buf.size()) {
                it = pending_.erase(it);
                continue;
            }
            result.insert(result.end(), buf.begin() + trim, buf.end());
        } else {
            result.insert(result.end(), buf.begin(), buf.end());
        }

        next_seq_ = seg_seq + static_cast<uint32_t>(buf.size());
        it = pending_.erase(it);
    }

    if (!result.empty()) consumed_any_ = true;
    return result;
}

size_t TcpStreamReassembler::pendingBytes() const {
    size_t total = 0;
    for (const auto& [seq, buf] : pending_) total += buf.size();
    return total;
}

}  // namespace dpi