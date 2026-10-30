#pragma once

#include <atomic>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "app/node.hpp"

namespace jn {

class ConsoleApp {
 public:
  ConsoleApp(NodeConfig config, Identity identity, const std::string& password);
  ~ConsoleApp();

  int run();

 private:
  void install_callbacks();
  void start_input_thread();
  void print_prompt();
  void print_help() const;
  void print_peers() const;
  void print_requests() const;
  void print_sessions() const;
  void print_history(std::size_t limit) const;
  void print_session_detail(const SessionView& view) const;
  void handle_command(const std::string& line);
  void send_active(const std::string& text);
  void select_session(const SessionView& view);

  Node node_;
  std::atomic<bool> quit_{false};
  std::atomic<bool> input_closed_{false};
  std::mutex queue_mutex_;
  std::deque<std::string> queue_;
  std::thread input_;
  std::optional<SessionId> active_;
};

}  // namespace jn
