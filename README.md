# FlowDPI

A small C++ deep-packet-inspection demo. It analyzes offline PCAP files or
captures live traffic through Npcap/libpcap in monitor-only mode. It reports
traffic matching IPv4, TCP/UDP port, or TLS SNI domain rules. Matching traffic
is **not dropped or blocked on the network**.

## Current capabilities

- Reads libpcap-format capture files and checks packet framing before use.
- Optionally captures from a selected live network interface.
- Parses Ethernet, IPv4, TCP, and UDP packets, including IPv4/TCP options.
- Tracks directional flows by five-tuple and reassembles common TCP segments.
- Extracts SNI from TLS ClientHello messages when visible in the capture.
- Reports matches for IPv4 addresses, TCP/UDP ports, and domains/subdomains.
- Can process PCAP input with multiple workers using `--workers`.

IPv6, VLAN decoding, full TCP overlap handling, encrypted ClientHello visibility,
and live packet dropping are outside the current scope.

## Build and test

With CMake and a C++17 compiler:

```powershell
cmake -S . -B build -DENABLE_SANITIZERS=OFF
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizers are enabled by default. Set `-DENABLE_SANITIZERS=OFF` if the
toolchain does not provide ASan/UBSan.

Live capture is optional. On Windows, install Npcap and extract the Npcap SDK.
Set `NPCAP_SDK` to the extracted SDK directory before configuring, for example:

```powershell
$env:NPCAP_SDK = "C:\path\to\npcap-sdk"
cmake -S . -B build -DENABLE_SANITIZERS=OFF
cmake --build build
```

On Linux/macOS, install libpcap and pkg-config. Reconfigure CMake after
installing capture dependencies. Capture may require administrator/root
privileges.

## Usage

Analyze a capture file:

```text
flowdpi capture.pcap --block-ip 10.0.0.1 --block-domain example.com --block-port tcp 443
```

Run live capture on an interface (use its Npcap/libpcap device name):

```text
flowdpi --live "\Device\NPF_{...}" --block-port tcp 443 --block-port udp 53
```

Press Ctrl+C to stop and print the report. A matching rule is reported as a
match only; it does not prevent the packet from reaching its destination.

## Architecture

```text
include/        public headers and core data types
src/            PCAP/live capture, parsing, reassembly, rules, engine, CLI
tests/          unit and end-to-end tests
```

## Next step

Platform-specific packet enforcement (for example, Windows Filtering Platform
or WinDivert) could be added later to drop traffic that matches a rule. That is
not implemented in this monitor-only version.
