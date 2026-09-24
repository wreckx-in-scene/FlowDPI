#include "block_rules.h"

#include "test_framework.h"

using namespace dpi;

TEST(blocks_exact_domain_match) {
    BlockRules rules;
    rules.addBlockedDomain("example.com");
    CHECK(rules.matchBlockedDomain("example.com") == "example.com");
}

TEST(blocks_subdomain_of_blocked_domain) {
    BlockRules rules;
    rules.addBlockedDomain("example.com");
    CHECK(rules.matchBlockedDomain("api.example.com") == "example.com");
    CHECK(rules.matchBlockedDomain("a.b.example.com") == "example.com");
}

TEST(does_not_block_unrelated_domain_sharing_a_suffix) {
    BlockRules rules;
    rules.addBlockedDomain("example.com");
    // "notexample.com" ends with the same characters as "example.com"
    // but is not a subdomain of it — a naive suffix-string check would
    // wrongly block this.
    CHECK(rules.matchBlockedDomain("notexample.com").empty());
}

TEST(does_not_block_unrelated_domain) {
    BlockRules rules;
    rules.addBlockedDomain("example.com");
    CHECK(rules.matchBlockedDomain("totally-unrelated.org").empty());
}

TEST(blocks_ip_added_to_rules) {
    BlockRules rules;
    uint32_t ip = 0x08080808;  // 8.8.8.8
    rules.addBlockedIp(ip);
    CHECK(rules.isBlockedIp(ip));
    CHECK(!rules.isBlockedIp(0x01010101));
}