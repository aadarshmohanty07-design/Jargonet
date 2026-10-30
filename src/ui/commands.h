#pragma once

#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace jn::ui {

enum class CommandKind {
  None,
  Help,
  Peers,
  Send,
  Relays,
  Status,
  Route,
  Hex,
  Clear,
  Quit,
  BareText,
  Unknown,
};

struct Command {
  CommandKind kind = CommandKind::None;
  std::string name;
  std::string message;
  int relays = 0;
  bool relays_set = false;
  std::string error;
  std::string raw;
};

// Splits an input line into a command. A leading '/' is required except for
// bare text, which the app maps to the single prior conversation.
Command parse_command(const std::string& line);

std::string help_text();

class CommandQueue {
 public:
  void push(Command command);
  std::vector<Command> drain();
  bool empty() const;

 private:
  mutable std::mutex mutex_;
  std::deque<Command> queue_;
};

}  // namespace jn::ui
