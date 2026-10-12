#pragma once
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "types.h"

namespace dpi {

// Holds a set of block rules: blocked IPv4 addresses and blocked domains
// (matched against the SNI extracted from a TLS ClientHello).
//
// Domain matching follows the common DNS-blocklist convention: a rule
// for "example.com" blocks that exact hostname *and* any subdomain of it
// ("api.example.com", "a.b.example.com", ...), but not a hostname that
// merely shares the suffix as a raw substring ("notexample.com" is NOT
// blocked by a rule for "example.com" — the match requires a "." right
// before the rule, not just matching trailing characters).
class BlockRules {
public:
    void addBlockedIp(uint32_t ip);
    void addBlockedDomain(const std::string& domain);
    void addBlockedPort(L4Protocol protocol, uint16_t port);

    bool isBlockedIp(uint32_t ip) const;
    bool isBlockedPort(L4Protocol protocol, uint16_t port) const;

    // Returns the specific rule that matched, or an empty string if
    // `hostname` isn't blocked by anything.
    std::string matchBlockedDomain(const std::string& hostname) const;

    size_t blockedIpCount() const { return blocked_ips_.size(); }
    size_t blockedDomainCount() const { return blocked_domains_.size(); }

private:
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<uint32_t> blocked_ports_;
    std::vector<std::string> blocked_domains_;  // small in practice; linear scan is fine

    static uint32_t portKey(L4Protocol protocol, uint16_t port);
};

}  // namespace dpi