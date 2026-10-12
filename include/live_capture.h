#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace dpi {

// Thin wrapper around libpcap live capture. Feeds each captured frame to
// a callback as raw bytes — the same shape as one pcap file record —
// so callers don't need a separate processing path for live vs. offline
// traffic; see main.cpp for how a captured frame is turned into the same
// RawPacket/ParsedPacket flow used for file replay.
//
// Only built when libpcap is found on the system (see CMakeLists.txt) —
// this is an optional capability, not a hard dependency, since the
// Windows/MinGW toolchain this project also targets doesn't have
// libpcap by default.
class LiveCapture {
public:
    using PacketCallback = std::function<void(const uint8_t* data, size_t len)>;

    // Opens `interface` (e.g. "eth0", "lo") for live capture. Returns
    // false with `error_out` set on failure — most commonly insufficient
    // privileges (raw capture needs root or CAP_NET_RAW on Linux) or an
    // interface name that doesn't exist.
    bool open(const std::string& interface, std::string& error_out);

    // Blocks, invoking `callback` for each captured packet, until
    // stop() is called (e.g. from a signal handler) or an error occurs.
    void loop(const PacketCallback& callback);

    // Safe to call from a signal handler or another thread — unblocks a
    // running loop().
    void stop();

    void close();

    ~LiveCapture();

private:
    // pcap_t*, kept opaque here so this header doesn't force every
    // includer to pull in <pcap/pcap.h>.
    void* handle_ = nullptr;
};

}  // namespace dpi