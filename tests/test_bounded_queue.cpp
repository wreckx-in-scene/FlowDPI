#include "bounded_queue.h"

#include <atomic>
#include <chrono>
#include <thread>

#include "test_framework.h"

using namespace dpi;

TEST(fifo_order_preserved) {
    BoundedQueue<int> q(10);
    for (int i = 0; i < 5; i++) CHECK(q.push(i));

    for (int i = 0; i < 5; i++) {
        int out = -1;
        CHECK(q.pop(out));
        CHECK_EQ(out, i);
    }
}

TEST(pop_blocks_until_item_available) {
    BoundedQueue<int> q(4);
    std::atomic<bool> popped{false};

    std::thread consumer([&] {
        int out = -1;
        q.pop(out);
        CHECK_EQ(out, 42);
        popped = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    CHECK(!popped);  // consumer should still be blocked, nothing pushed yet

    q.push(42);
    consumer.join();
    CHECK(popped);
}

TEST(push_blocks_when_full_backpressure) {
    BoundedQueue<int> q(2);
    CHECK(q.push(1));
    CHECK(q.push(2));  // now full

    std::atomic<bool> third_pushed{false};
    std::thread producer([&] {
        q.push(3);  // should block until a slot frees up
        third_pushed = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    CHECK(!third_pushed);  // still full, producer should be blocked

    int out = -1;
    q.pop(out);  // frees a slot
    producer.join();
    CHECK(third_pushed);
}

TEST(close_unblocks_waiting_pop) {
    BoundedQueue<int> q(4);
    std::atomic<bool> returned{false};
    std::atomic<bool> result{true};

    std::thread consumer([&] {
        int out;
        result = q.pop(out);  // nothing ever pushed — should unblock via close(), return false
        returned = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    CHECK(!returned);

    q.close();
    consumer.join();
    CHECK(returned);
    CHECK(!result);
}

TEST(close_drains_existing_items_before_pop_fails) {
    BoundedQueue<int> q(4);
    q.push(1);
    q.push(2);
    q.close();  // no more pushes allowed, but existing items still pop

    int out = -1;
    CHECK(q.pop(out));
    CHECK_EQ(out, 1);
    CHECK(q.pop(out));
    CHECK_EQ(out, 2);

    CHECK(!q.pop(out));  // now drained — pop should fail
}

TEST(push_fails_after_close) {
    BoundedQueue<int> q(4);
    q.close();
    CHECK(!q.push(1));
}