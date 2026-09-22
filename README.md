# DPI Engine

A deep packet inspection engine, built up in layers instead of one drop.

## Status: Milestone 1 — core parsing

- `PcapReader` — reads libpcap-format capture files, byte-order aware, rejects malformed/hostile framing instead of trusting file-declared lengths.
- `PacketParser` — Ethernet → IPv4 → TCP/UDP. Header lengths (IPv4 IHL, TCP data offset) are read and walked, not assumed, so packets with IP/TCP options parse correctly.
- `FiveTuple` / `FiveTupleHash` — flow identity, ready for a flow table.
- Built and tested under `-fsanitize=address,undefined` by default.

Not yet built: TLS SNI extraction, TCP stream reassembly, flow-level blocking, concurrency, live capture. See the milestone plan below.

## Build & test

```bash
mkdir build && cd build
cmake ..
make
./dpi_tests
```

Sanitizers are on by default (`ENABLE_SANITIZERS=ON`). To build without them (e.g. for a later perf benchmark run):

```bash
cmake .. -DENABLE_SANITIZERS=OFF
```

## Layout

```
include/        public headers
src/            implementation
tests/          self-contained test framework + unit tests (no external deps)
```

## Milestone plan

1. **Core parsing correctness** (this milestone) — pcap reading, Ethernet/IP/TCP/UDP parsing, five-tuple, unit tests, ASan/UBSan clean.
2. **TLS SNI extraction** — TLV-walking extension parser, per-flow TCP reassembly so a ClientHello split across segments still parses.
3. **Single-threaded engine end-to-end** — rule engine, flow-level blocking, report generation.
4. **Concurrency layer** — reader → load-balancer → fast-path → writer pipeline.
5. **Live capture + latency instrumentation** — libpcap/AF_PACKET live interface, per-packet p50/p99/p999 latency histogram.
6. **Polish** — CI, fuzz target on the TLS parser, benchmark suite.
