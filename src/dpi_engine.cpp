#include "dpi_engine.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <utility>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "tls_parser.h"

namespace dpi {

namespace {
using Clock = std::chrono::steady_clock;

std::string ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    return oss.str();
}

std::string describeDirection(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    return ipToString(src_ip) + ":" + std::to_string(src_port) + " -> " + ipToString(dst_ip) + ":" +
           std::to_string(dst_port);
}
}  // namespace

LatencyPercentiles computeLatencyPercentiles(std::vector<double> latencies_ns) {
    LatencyPercentiles result;
    if (latencies_ns.empty()) return result;

    std::sort(latencies_ns.begin(), latencies_ns.end());
    auto pct = [&](double p) {
        size_t idx = static_cast<size_t>(p * static_cast<double>(latencies_ns.size() - 1));
        return latencies_ns[idx];
    };
    result.p50 = pct(0.50);
    result.p99 = pct(0.99);
    result.p999 = pct(0.999);
    result.max_ns = latencies_ns.back();
    return result;
}

DpiEngine::DpiEngine(BlockRules rules) : rules_(std::move(rules)) {}

bool DpiEngine::processFile(const std::string& pcap_path) {
    PcapReader reader;
    if (!reader.open(pcap_path)) return false;

    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        processPacket(std::move(raw));
    }
    return true;
}

void DpiEngine::processPacket(RawPacket raw) {
    ParsedPacket parsed;
    if (!PacketParser::parse(raw, parsed)) return;  // malformed/unparseable — skip, don't crash
    processParsedPacket(std::move(raw), parsed);
}

void DpiEngine::processParsedPacket(RawPacket raw, const ParsedPacket& parsed) {
    if (!parsed.has_ip) return;  // non-IPv4 traffic out of scope for now

    auto t0 = Clock::now();

    report_.total_packets++;

    FiveTuple tuple = parsed.tuple();
    auto it = flows_.find(tuple);
    if (it == flows_.end()) {
        FlowState fresh;
        fresh.tuple = tuple;
        it = flows_.emplace(tuple, std::move(fresh)).first;
        report_.total_flows++;
    }
    FlowState& flow = it->second;

    flow.packet_count++;
    flow.byte_count += raw.data.size();

    // Already decided — flow-level blocking means we don't re-inspect
    // every subsequent packet once a flow is condemned.
    if (flow.blocked) {
        report_.blocked_packets++;
        report_.packet_latencies_ns.push_back(
            std::chrono::duration<double, std::nano>(Clock::now() - t0).count());
        return;
    }

    // IP-level block check first: cheap, and doesn't need payload/reassembly.
    if (rules_.isBlockedIp(parsed.dst_ip) || rules_.isBlockedIp(parsed.src_ip)) {
        flow.blocked = true;
        flow.block_reason = "matched blocked IP rule";
        report_.blocked_flows++;
        report_.blocked_packets++;
        report_.blocked_entries.push_back(
            {describeDirection(parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port),
             flow.block_reason});
        report_.packet_latencies_ns.push_back(
            std::chrono::duration<double, std::nano>(Clock::now() - t0).count());
        return;
    }

    if (parsed.has_l4 &&
        (rules_.isBlockedPort(parsed.protocol, parsed.dst_port) ||
         rules_.isBlockedPort(parsed.protocol, parsed.src_port))) {
        flow.blocked = true;
        uint16_t matched_port = rules_.isBlockedPort(parsed.protocol, parsed.dst_port)
                                    ? parsed.dst_port
                                    : parsed.src_port;
        flow.block_reason =
            std::string("matched blocked ") +
            (parsed.protocol == L4Protocol::TCP ? "TCP" : "UDP") + " port " +
            std::to_string(matched_port) + " rule";
        report_.blocked_flows++;
        report_.blocked_packets++;
        report_.blocked_entries.push_back(
            {describeDirection(parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port),
             flow.block_reason});
        report_.packet_latencies_ns.push_back(
            std::chrono::duration<double, std::nano>(Clock::now() - t0).count());
        return;
    }

    // TLS SNI extraction, only while a direction hasn't been resolved yet.
    if (parsed.protocol == L4Protocol::TCP && parsed.has_l4 &&
        flow.sni_status == SniAttemptStatus::Pending) {
        flow.reassembler.addSegment(parsed.tcp_seq, parsed.payload, parsed.payload_len);
        tryResolveSni(flow);
    }

    if (flow.sni_status == SniAttemptStatus::Found) {
        std::string matched_rule = rules_.matchBlockedDomain(flow.sni);
        if (!matched_rule.empty()) {
            flow.blocked = true;
            flow.block_reason = "matched blocked domain rule (" + matched_rule + ")";
            report_.blocked_flows++;
            report_.blocked_packets++;
            report_.blocked_entries.push_back(
                {describeDirection(parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port) +
                     " (" + flow.sni + ")",
                 flow.block_reason});
        } else {
            report_.observed_snis.push_back(flow.sni);
        }
    }

    report_.packet_latencies_ns.push_back(
        std::chrono::duration<double, std::nano>(Clock::now() - t0).count());
}

void DpiEngine::tryResolveSni(FlowState& flow) {
    auto chunk = flow.reassembler.pullContiguous();
    if (!chunk.empty()) {
        flow.sni_buffer.insert(flow.sni_buffer.end(), chunk.begin(), chunk.end());
    }
    if (flow.sni_buffer.empty()) return;  // nothing accumulated yet to try

    std::string sni;
    auto status = tryExtractSni(flow.sni_buffer.data(), flow.sni_buffer.size(), sni);

    switch (status) {
        case TlsParseStatus::Incomplete:
            if (flow.sni_buffer.size() > MAX_REASSEMBLY_BYTES) {
                flow.sni_status = SniAttemptStatus::GaveUp;
                flow.sni_buffer.clear();
                flow.sni_buffer.shrink_to_fit();
            }
            return;  // otherwise: keep waiting for more segments
        case TlsParseStatus::Found:
            flow.sni = std::move(sni);
            flow.sni_status = SniAttemptStatus::Found;
            break;
        case TlsParseStatus::NoSni:
            flow.sni_status = SniAttemptStatus::NoSni;
            break;
        case TlsParseStatus::NotTls:
            flow.sni_status = SniAttemptStatus::NotTls;
            break;
        case TlsParseStatus::Malformed:
            flow.sni_status = SniAttemptStatus::Malformed;
            break;
    }

    // A decision (of any kind) was reached — the buffer's done its job.
    flow.sni_buffer.clear();
    flow.sni_buffer.shrink_to_fit();
}

std::string DpiEngine::renderReport() const {
    std::ostringstream out;
    out << "=== FlowDPI Report ===\n";
    out << "Total packets:   " << report_.total_packets << "\n";
    out << "Total flows:     " << report_.total_flows << "\n";
    out << "Rule-matched flows:   " << report_.blocked_flows << "\n";
    out << "Rule-matched packets: " << report_.blocked_packets << "\n";

    if (!report_.blocked_entries.empty()) {
        out << "\n-- Rule matches --\n";
        for (const auto& e : report_.blocked_entries) {
            out << "  " << e.description << "  [" << e.reason << "]\n";
        }
    }

    if (!report_.observed_snis.empty()) {
        out << "\n-- Observed SNIs (allowed) --\n";
        for (const auto& s : report_.observed_snis) {
            out << "  " << s << "\n";
        }
    }

    if (!report_.packet_latencies_ns.empty()) {
        auto lat = computeLatencyPercentiles(report_.packet_latencies_ns);
        out << "\n-- Processing latency (per packet, excludes pcap I/O) --\n";
        out << "  p50:  " << lat.p50 << " ns\n";
        out << "  p99:  " << lat.p99 << " ns\n";
        out << "  p999: " << lat.p999 << " ns\n";
        out << "  max:  " << lat.max_ns << " ns\n";
    }

    return out.str();
}

}  // namespace dpi