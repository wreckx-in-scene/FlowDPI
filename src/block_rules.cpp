#include "block_rules.h"

namespace dpi {

namespace {
bool matchesRule(const std::string& hostname, const std::string& rule) {
    if (hostname == rule) return true;

    // Subdomain match: hostname must end with "." + rule, not just share
    // trailing characters with it.
    std::string suffix = "." + rule;
    if (hostname.size() <= suffix.size()) return false;
    return hostname.compare(hostname.size() - suffix.size(), suffix.size(), suffix) == 0;
}
}  // namespace

void BlockRules::addBlockedIp(uint32_t ip) { blocked_ips_.insert(ip); }

void BlockRules::addBlockedDomain(const std::string& domain) { blocked_domains_.push_back(domain); }

uint32_t BlockRules::portKey(L4Protocol protocol, uint16_t port) {
    return (static_cast<uint32_t>(protocol) << 16) | port;
}

void BlockRules::addBlockedPort(L4Protocol protocol, uint16_t port) {
    if (protocol == L4Protocol::TCP || protocol == L4Protocol::UDP) {
        blocked_ports_.insert(portKey(protocol, port));
    }
}

bool BlockRules::isBlockedIp(uint32_t ip) const { return blocked_ips_.count(ip) != 0; }

bool BlockRules::isBlockedPort(L4Protocol protocol, uint16_t port) const {
    return blocked_ports_.count(portKey(protocol, port)) != 0;
}

std::string BlockRules::matchBlockedDomain(const std::string& hostname) const {
    for (const auto& rule : blocked_domains_) {
        if (matchesRule(hostname, rule)) return rule;
    }
    return "";
}

}  // namespace dpi