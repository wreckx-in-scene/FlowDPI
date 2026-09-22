#pragma once
#include <functional>
#include <iostream>
#include <string>
#include <vector>

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct TestRegistrar {
    TestRegistrar(const std::string& name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline int& failure_count() {
    static int failures = 0;
    return failures;
}

#define TEST(name)                                                  \
    void test_##name();                                             \
    TestRegistrar registrar_##name(#name, test_##name);              \
    void test_##name()

#define CHECK(cond)                                                              \
    do {                                                                          \
        if (!(cond)) {                                                            \
            std::cerr << "  FAIL: " << #cond << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
            failure_count()++;                                                    \
        }                                                                          \
    } while (0)

#define CHECK_EQ(a, b)                                                                        \
    do {                                                                                        \
        auto va = (a);                                                                          \
        auto vb = (b);                                                                          \
        if (!(va == vb)) {                                                                       \
            std::cerr << "  FAIL: " << #a << " == " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
            failure_count()++;                                                                   \
        }                                                                                         \
    } while (0)

inline int run_all_tests() {
    int total = 0;
    for (auto& t : registry()) {
        std::cout << "[RUN]  " << t.name << "\n";
        int before = failure_count();
        t.fn();
        total++;
        if (failure_count() == before) std::cout << "[PASS] " << t.name << "\n";
    }
    std::cout << "\n" << total << " tests run, " << failure_count() << " failures\n";
    return failure_count() == 0 ? 0 : 1;
}
