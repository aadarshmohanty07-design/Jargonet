#pragma once

#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "ui/commands.h"
#include "ui/events.h"
#include "ui/renderer.h"

namespace jn::ui {

struct StartupInfo {
  std::string version = "0.1";
  std::string name;
  std::string fingerprint;
  std::string listen_ip = "0.0.0.0";
  int port = 9001;
  int discovery_port = 9999;
};

class App {
 public:
  App(EventQueue& events, CommandQueue& commands, IRenderer& renderer);
  ~App();

  App(const App&) = delete;
  App& operator=(const App&) = delete;

  int run(const StartupInfo& info);
  void stop();

 private:
  void render_loop();
  void observe(const UIEvent& event);
  void handle_line(const std::string& line);
  void enqueue_system(const std::string& text);
  void enqueue_error(const std::string& text);
  void print_banner() const;

  EventQueue& events_;
  CommandQueue& commands_;
  IRenderer& renderer_;
  std::atomic<bool> running_{true};
  std::thread render_thread_;
  mutable std::mutex conversations_mutex_;
  std::set<std::string> conversations_;
  bool quit_queued_ = false;
};

}  // namespace jn::ui
