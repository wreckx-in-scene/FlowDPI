#include "pcap_reader.h"

namespace dpi {

namespace {
constexpr uint32_t PCAP_MAGIC = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

uint16_t swap16(uint16_t v) {
    return static_cast<uint16_t>(((v & 0x00FFu) << 8) | ((v & 0xFF00u) >> 8));
}
}  // namespace

PcapReader::~PcapReader() { close(); }

bool PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) return false;

    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(global_header_));
    if (!file_ || static_cast<size_t>(file_.gcount()) != sizeof(global_header_)) {
        close();
        return false;
    }

    if (global_header_.magic_number == PCAP_MAGIC) {
        swapped_ = false;
    } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED) {
        swapped_ = true;
        global_header_.version_major = swap16(global_header_.version_major);
        global_header_.version_minor = swap16(global_header_.version_minor);
        global_header_.snaplen = swap32(global_header_.snaplen);
        global_header_.network = swap32(global_header_.network);
    } else {
        close();
        return false;  // not a pcap file we recognize
    }

    return true;
}

bool PcapReader::readNextPacket(RawPacket& out) {
    if (!file_.is_open()) return false;

    PcapPacketHeader hdr{};
    file_.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!file_ || static_cast<size_t>(file_.gcount()) != sizeof(hdr)) {
        return false;  // clean EOF or truncated header — either way, stop
    }

    if (swapped_) {
        hdr.ts_sec = swap32(hdr.ts_sec);
        hdr.ts_usec = swap32(hdr.ts_usec);
        hdr.incl_len = swap32(hdr.incl_len);
        hdr.orig_len = swap32(hdr.orig_len);
    }

    // Refuse to trust an incl_len bigger than the file's own declared
    // snaplen — guards against a corrupted/hostile capture forcing a huge
    // allocation.
    if (global_header_.snaplen != 0 && hdr.incl_len > global_header_.snaplen) {
        return false;
    }

    out.header = hdr;
    out.data.resize(hdr.incl_len);
    if (hdr.incl_len > 0) {
        file_.read(reinterpret_cast<char*>(out.data.data()), hdr.incl_len);
        if (!file_ || static_cast<uint32_t>(file_.gcount()) != hdr.incl_len) {
            return false;  // truncated packet body
        }
    }

    return true;
}

void PcapReader::close() {
    if (file_.is_open()) file_.close();
}

}  // namespace dpi
