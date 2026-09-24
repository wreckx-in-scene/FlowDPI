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

bool BlockRules::isBlockedIp(uint32_t ip) const { return blocked_ips_.count(ip) != 0; }

std::string BlockRules::matchBlockedDomain(const std::string& hostname) const {
    for (const auto& rule : blocked_domains_) {
        if (matchesRule(hostname, rule)) return rule;
    }
    return "";
}

}  // namespace dpi