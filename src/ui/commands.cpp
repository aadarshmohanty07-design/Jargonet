#include "ui/commands.h"

#include <charconv>
#include <cctype>
#include <sstream>
#include <string_view>
#include <utility>

namespace jn::ui {
namespace {

std::string trim_copy(std::string_view text) {
  std::size_t begin = 0;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
  std::size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
  return std::string(text.substr(begin, end - begin));
}

std::vector<std::string> split_whitespace(const std::string& line) {
  std::istringstream stream(line);
  std::vector<std::string> parts;
  std::string part;
  while (stream >> part) parts.push_back(part);
  return parts;
}

std::string join_from(const std::vector<std::string>& parts, std::size_t start) {
  std::string out;
  for (std::size_t i = start; i < parts.size(); ++i) {
    if (!out.empty()) out.push_back(' ');
    out += parts[i];
  }
  return out;
}

bool parse_positive_int(const std::string& text, int& out) {
  if (text.empty()) return false;
  int value = 0;
  const char* begin = text.data();
  const char* end = begin + text.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end || value <= 0) return false;
  out = value;
  return true;
}

}  // namespace

Command parse_command(const std::string& line) {
  Command command;
  command.raw = line;
  const std::string trimmed = trim_copy(line);
  if (trimmed.empty()) return command;

  if (trimmed.front() != '/') {
    command.kind = CommandKind::BareText;
    command.message = trimmed;
    return command;
  }

  const std::vector<std::string> parts = split_whitespace(trimmed);
  if (parts.empty()) return command;
  const std::string& head = parts[0];

  if (head == "/help") {
    command.kind = CommandKind::Help;
  } else if (head == "/peers") {
    command.kind = CommandKind::Peers;
  } else if (head == "/relays") {
    command.kind = CommandKind::Relays;
  } else if (head == "/status") {
    command.kind = CommandKind::Status;
  } else if (head == "/clear") {
    command.kind = CommandKind::Clear;
  } else if (head == "/quit") {
    command.kind = CommandKind::Quit;
  } else if (head == "/route" || head == "/hex") {
    command.kind = head == "/route" ? CommandKind::Route : CommandKind::Hex;
    if (parts.size() != 2 || (parts[1] != "on" && parts[1] != "off")) {
      command.error = "usage: " + head + " on|off";
    } else {
      command.name = parts[1];
    }
  } else if (head == "/send") {
    command.kind = CommandKind::Send;
    if (parts.size() < 3) {
      command.error = "usage: /send <name> [--relays N] <message>";
      return command;
    }
    if (parts[1].rfind("--", 0) == 0) {
      command.error = "send needs a peer name first";
      return command;
    }
    command.name = parts[1];

    std::vector<std::string> words;
    for (std::size_t i = 2; i < parts.size(); ++i) {
      if (parts[i] != "--relays") {
        words.push_back(parts[i]);
        continue;
      }
      if (i + 1 >= parts.size()) {
        command.error = "usage: /send <name> --relays <N> <message>";
        return command;
      }
      int relays = 0;
      if (!parse_positive_int(parts[i + 1], relays)) {
        command.error = "--relays needs a positive number";
        return command;
      }
      command.relays = relays;
      command.relays_set = true;
      ++i;
    }
    if (words.empty()) {
      command.error = "usage: /send <name> [--relays N] <message>";
      return command;
    }
    command.message = join_from(words, 0);
  } else {
    command.kind = CommandKind::Unknown;
    command.name = head;
  }

  return command;
}

std::string help_text() {
  return
      "Commands\n"
      "  /help                  show this list\n"
      "  /peers                 list online peers\n"
      "  /relays                list peers eligible as relays\n"
      "  /send <name> <msg>     direct encrypted send\n"
      "  /send <name> --relays <N> <msg>   onion-routed send\n"
      "  /status                show name, fingerprint, address and counts\n"
      "  /route on|off          show or hide the send route\n"
      "  /hex on|off            show full relay ciphertext hex\n"
      "  /clear                 clear the log pane\n"
      "  /quit                  broadcast BYE and exit\n"
      "Bare text goes to your only conversation.";
}

void CommandQueue::push(Command command) {
  std::lock_guard<std::mutex> lock(mutex_);
  queue_.push_back(std::move(command));
}

std::vector<Command> CommandQueue::drain() {
  std::vector<Command> out;
  std::lock_guard<std::mutex> lock(mutex_);
  out.reserve(queue_.size());
  while (!queue_.empty()) {
    out.push_back(std::move(queue_.front()));
    queue_.pop_front();
  }
  return out;
}

bool CommandQueue::empty() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return queue_.empty();
}

}  // namespace jn::ui
