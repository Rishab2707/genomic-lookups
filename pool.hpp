#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <queue>
#include <utility>
#include <vector>

// Thread-safe bounded FIFO queue for producer-consumer cryptographic pooling
template <typename T> class ThreadSafeQueue {
public:
  explicit ThreadSafeQueue(size_t max_size = 100)
      : max_size_(max_size), stopped_(false) {}

  // Pushes an item into the queue.
  // Blocks if the queue reaches max_size (provides backpressure to producer).
  // Returns false if the queue has been stopped.
  bool push(T item) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_not_full_.wait(
        lock, [this]() { return stopped_ || queue_.size() < max_size_; });
    if (stopped_)
      return false;
    queue_.push(std::move(item));
    cv_not_empty_.notify_one();
    return true;
  }

  // Pops an item from the queue.
  // Blocks if the queue is empty (handles buffer underflow without CPU
  // polling). Returns false if the queue is stopped and empty.
  bool pop(T &item) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_not_empty_.wait(lock, [this]() { return stopped_ || !queue_.empty(); });
    if (queue_.empty())
      return false;
    item = std::move(queue_.front());
    queue_.pop();
    cv_not_full_.notify_one();
    return true;
  }

  // Non-blocking pop attempt
  bool try_pop(T &item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty())
      return false;
    item = std::move(queue_.front());
    queue_.pop();
    cv_not_full_.notify_one();
    return true;
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  void stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopped_ = true;
    }
    cv_not_empty_.notify_all();
    cv_not_full_.notify_all();
  }

private:
  mutable std::mutex mutex_;
  std::condition_variable cv_not_empty_;
  std::condition_variable cv_not_full_;
  std::queue<T> queue_;
  size_t max_size_;
  bool stopped_;
};

// Item stored in Client's local offline pool
struct ClientPoolItem {
  uint64_t dpf_id; // Unique sync ID
  size_t r_index;  // The random dummy index in [0, db_blocks - 1]
};

// Item stored in Server's offline pool
struct ServerPoolItem {
  uint64_t dpf_id; // Must match Client's sync ID
  std::vector<bool>
      expanded_vector; // Pre-expanded boolean vector for O(1) online CPU time
};
