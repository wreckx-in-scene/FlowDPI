#include "live_capture.h"

#include <pcap/pcap.h>

namespace dpi {

namespace {
struct CallbackContext {
    const LiveCapture::PacketCallback* callback;
};

void pcapTrampoline(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
    auto* ctx = reinterpret_cast<CallbackContext*>(user);
    (*ctx->callback)(bytes, header->caplen);
}
}  // namespace

bool LiveCapture::open(const std::string& interface_name, std::string& error_out) {
    char errbuf[PCAP_ERRBUF_SIZE];
    // snaplen 65535 (full packet), promiscuous off (traffic to/from this
    // host only — promiscuous mode needs the same elevated privilege
    // either way, but this is the less surprising default), 1000ms read
    // timeout so pcap_loop periodically checks for a pending
    // pcap_breakloop() instead of blocking indefinitely on a quiet link.
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 65535, 0, 1000, errbuf);
    if (!handle) {
        error_out = errbuf;
        return false;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        error_out = "Selected interface does not provide Ethernet frames";
        pcap_close(handle);
        return false;
    }
    handle_ = handle;
    return true;
}

void LiveCapture::loop(const PacketCallback& callback) {
    if (!handle_) return;
    CallbackContext ctx{&callback};
    pcap_loop(static_cast<pcap_t*>(handle_), -1, pcapTrampoline, reinterpret_cast<u_char*>(&ctx));
}

void LiveCapture::stop() {
    if (handle_) pcap_breakloop(static_cast<pcap_t*>(handle_));
}

void LiveCapture::close() {
    if (handle_) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
}

LiveCapture::~LiveCapture() { close(); }

}  // namespace dpi