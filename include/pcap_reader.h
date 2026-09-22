#pragma once
#include <fstream>
#include <string>

#include "types.h"

namespace dpi {

// Reads packets from a libpcap-format capture file.
//
// Deliberately does not trust the file: incl_len is checked against
// snaplen before we allocate/read, and a truncated header or packet body
// is treated as end-of-stream rather than undefined behavior. A hostile
// or corrupted pcap should make this return false, never crash.
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    // Opens `filename` and validates the 24-byte global header.
    // Returns false if the file can't be opened or isn't a valid pcap.
    bool open(const std::string& filename);

    // Reads the next packet into `out`. Returns false at EOF or on any
    // framing error (truncated header, truncated body, oversized incl_len).
    bool readNextPacket(RawPacket& out);

    void close();

    bool isOpen() const { return file_.is_open(); }
    uint32_t snaplen() const { return global_header_.snaplen; }
    bool isSwapped() const { return swapped_; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_{};
    bool swapped_ = false;  // true if the file's byte order differs from host
};

}  // namespace dpi
