#include "pcap_reader.h"

#include <fstream>
#include <cstdio>
#include <unistd.h>

#include "test_framework.h"

using namespace dpi;

namespace {

std::string makeTempPath() {
    static int counter = 0;
    return "/tmp/dpi_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) + ".pcap";
}

std::string writeTempPcap(const std::vector<std::vector<uint8_t>>& packets) {
    std::string path = makeTempPath();
    std::ofstream f(path, std::ios::binary);

    PcapGlobalHeader gh{};
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1;  // Ethernet
    f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    for (const auto& pkt : packets) {
        PcapPacketHeader ph{};
        ph.ts_sec = 0;
        ph.ts_usec = 0;
        ph.incl_len = static_cast<uint32_t>(pkt.size());
        ph.orig_len = static_cast<uint32_t>(pkt.size());
        f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        f.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
    }

    f.close();
    return path;
}

}  // namespace

TEST(reads_valid_pcap_with_multiple_packets) {
    std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> pkt2 = {6, 7, 8};
    std::string path = writeTempPcap({pkt1, pkt2});

    PcapReader reader;
    CHECK(reader.open(path));
    CHECK_EQ(reader.snaplen(), 65535u);

    RawPacket raw;
    CHECK(reader.readNextPacket(raw));
    CHECK(raw.data == pkt1);

    CHECK(reader.readNextPacket(raw));
    CHECK(raw.data == pkt2);

    CHECK(!reader.readNextPacket(raw));  // EOF

    std::remove(path.c_str());
}

TEST(rejects_file_with_bad_magic) {
    std::string path = makeTempPath();
    std::ofstream f(path, std::ios::binary);
    uint32_t bad_magic = 0xdeadbeef;
    f.write(reinterpret_cast<const char*>(&bad_magic), sizeof(bad_magic));
    f.close();

    PcapReader reader;
    CHECK(!reader.open(path));

    std::remove(path.c_str());
}

TEST(rejects_truncated_global_header) {
    std::string path = makeTempPath();
    std::ofstream f(path, std::ios::binary);
    uint8_t too_short[4] = {0xd4, 0xc3, 0xb2, 0xa1};
    f.write(reinterpret_cast<const char*>(too_short), sizeof(too_short));
    f.close();

    PcapReader reader;
    CHECK(!reader.open(path));

    std::remove(path.c_str());
}

TEST(rejects_packet_claiming_more_than_snaplen) {
    std::string path = makeTempPath();
    std::ofstream f(path, std::ios::binary);

    PcapGlobalHeader gh{};
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.snaplen = 100;
    gh.network = 1;
    f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    PcapPacketHeader ph{};
    ph.incl_len = 999999;  // lies about how much data follows
    ph.orig_len = 999999;
    f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
    f.close();

    PcapReader reader;
    CHECK(reader.open(path));
    RawPacket raw;
    CHECK(!reader.readNextPacket(raw));  // must refuse, not try to allocate/read 999999 bytes

    std::remove(path.c_str());
}
