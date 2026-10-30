#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// windows.h defines ERROR as 0; the shared event name wins.
#if defined(ERROR)
#undef ERROR
#endif

namespace jn::ui {

enum class EventType : std::uint8_t {
  PEER_JOINED,
  PEER_LEFT,
  MESSAGE_SENT,
  MESSAGE_RECEIVED,
  RELAY_RECEIVED,
  RELAY_FORWARDED,
  ROUTE_STARTED,
  ROUTE_COMPLETED,
  STATUS_UPDATE,
  ERROR,
  SYSTEM,
};

// Shared with the backend. Do not change a field without updating both sides.
// Optional-text convention: PEER_JOINED.sys_msg carries the endpoint,
// PEER_LEFT.sys_msg the elapsed time, and STATUS_UPDATE.sys_msg the counters.
struct UIEvent {
  EventType type = EventType::SYSTEM;
  std::string from;
  std::string to;
  std::string payload_hex;
  std::string plaintext;
  std::string fingerprint;
  std::string route;
  std::string error_msg;
  std::string sys_msg;
  int size_bytes = 0;
  std::chrono::system_clock::time_point ts = std::chrono::system_clock::now();
};

class EventQueue {
 public:
  void push(UIEvent event) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(std::move(event));
  }

  std::vector<UIEvent> drain() {
    std::vector<UIEvent> out;
    std::lock_guard<std::mutex> lock(mutex_);
    out.reserve(queue_.size());
    while (!queue_.empty()) {
      out.push_back(std::move(queue_.front()));
      queue_.pop_front();
    }
    return out;
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

 private:
  mutable std::mutex mutex_;
  std::deque<UIEvent> queue_;
};

}  // namespace jn::ui
