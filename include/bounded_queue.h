#pragma once
#include <condition_variable>
#include <mutex>
#include <queue>
#include <utility>

namespace dpi {

// A fixed-capacity, thread-safe queue with blocking push/pop.
//
// push() blocks while full — deliberate backpressure: a slow consumer
// throttles the producer instead of the queue growing unbounded. pop()
// blocks while empty. close() wakes every waiter; after close(), push()
// fails immediately, and pop() keeps returning already-queued items
// until drained, then fails too — that's how a consumer thread knows to
// exit cleanly once the producer is done and the backlog is cleared.
//
// Mutex + condition variables, not lock-free — see NOTES.md for why that
// tradeoff was made for this milestone rather than a lock-free ring
// buffer.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    // Returns false if the queue was closed before space opened up.
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < capacity_ || closed_; });
        if (closed_) return false;
        queue_.push(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    // Returns false once closed and drained.
    bool pop(T& out) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        not_full_.notify_one();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::queue<T> queue_;
    size_t capacity_;
    bool closed_ = false;
};

}  // namespace dpi