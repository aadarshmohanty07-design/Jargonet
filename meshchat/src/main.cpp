#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "core/encoding.hpp"
#include "mesh_node.hpp"

namespace {

using jn::Bytes;
using jn::Endpoint;
using jn::hex_encode;
using jn::trim;
using jn::mesh::MeshNode;
using jn::mesh::PeerInfo;
using jn::mesh::RelayReport;

constexpr const char* kReset = "\033[0m";
constexpr const char* kCyan = "\033[36m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kRed = "\033[31m";
constexpr const char* kGray = "\033[90m";

bool stdout_is_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stdout)) != 0;
#else
  return ::isatty(STDOUT_FILENO) != 0;
#endif
}

bool stdin_is_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return ::isatty(STDIN_FILENO) != 0;
#endif
}

bool enable_virtual_terminal() {
#ifdef _WIN32
  HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (handle == INVALID_HANDLE_VALUE || !GetConsoleMode(handle, &mode)) return false;
  return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
  return true;
#endif
}

class Printer {
 public:
  Printer(bool color, bool prompts) : color_(color), prompts_(prompts) {}

  void line(const char* color, const std::string& text, bool async = false) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (async) std::cout << '\n';
    if (color_ && color) std::cout << color << text << kReset << '\n';
    else std::cout << text << '\n';
    std::cout.flush();
  }

  void prompt() {
    if (!prompts_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << (color_ ? kCyan : "") << "> " << (color_ ? kReset : "") << std::flush;
  }

 private:
  std::mutex mutex_;
  bool color_;
  bool prompts_;
};

std::string format_peers(const std::vector<PeerInfo>& peers) {
  if (peers.empty()) return "Online: (none)";
  std::string out = "Online: ";
  for (std::size_t i = 0; i < peers.size(); ++i) {
    if (i != 0) out += ", ";
    out += peers[i].name + " (" + peers[i].short_fingerprint() + ")";
  }
  return out;
}

void print_usage(const char* program) {
  std::cout
      << "meshchat - real LAN onion-routing prototype\n\n"
      << "Usage:\n"
      << "  " << program
      << " --name Alice [--port 9001] [--peers ip:port,...] [--no-color]\n\n"
      << "  --name NAME       display name (letters, digits, _ or -)\n"
      << "  --port PORT       unicast UDP port (default: ephemeral, advertised in HELLO)\n"
      << "  --peers LIST      manual unicast seeds for broadcast-isolated networks\n"
      << "  --no-color        plain output\n\n"
      << "Commands:\n"
      << "  send <name> <message> [--relays N] [--verbose-route]\n"
      << "  peers\n"
      << "  quit\n\n"
      << "Discovery uses UDP broadcast to 255.255.255.255:9999 every 2 seconds.\n"
      << "Every instance binds 9999 with address reuse; relay packets use the\n"
      << "instance's unicast --port.\n";
}

bool parse_port(const std::string& text, std::uint16_t& port) {
  try {
    const unsigned long value = std::stoul(text);
    if (value > 65535) return false;
    port = static_cast<std::uint16_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

std::vector<Endpoint> parse_seeds(const std::string& text, std::string& error) {
  std::vector<Endpoint> seeds;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::string item =
        trim(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
    if (!item.empty()) {
      auto endpoint = Endpoint::parse(item);
      if (!endpoint) {
        error = "invalid --peers endpoint: " + item;
        return {};
      }
      seeds.push_back(*endpoint);
    }
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return seeds;
}

struct SendCommand {
  std::string target;
  std::string message;
  int relays = 0;
  bool verbose = false;
  std::string error;
};

SendCommand parse_send(const std::string& text) {
  SendCommand result;
  std::istringstream stream(text);
  std::string token;
  if (!(stream >> result.target)) {
    result.error = "usage: send <name> <message> [--relays N] [--verbose-route]";
    return result;
  }
  std::vector<std::string> words;
  while (stream >> token) {
    if (token == "--relays") {
      std::string value;
      if (!(stream >> value)) {
        result.error = "--relays needs a number";
        return result;
      }
      try {
        result.relays = std::stoi(value);
      } catch (...) {
        result.error = "--relays needs a number";
        return result;
      }
      if (result.relays < 0 || result.relays > 4) {
        result.error = "--relays must be between 0 and 4";
        return result;
      }
    } else if (token == "--verbose-route") {
      result.verbose = true;
    } else {
      words.push_back(token);
    }
  }
  for (const auto& word : words) {
    if (!result.message.empty()) result.message.push_back(' ');
    result.message += word;
  }
  if (result.message.empty()) result.error = "message is empty";
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  MeshNode::Config config;
  bool no_color = false;
  bool have_name = false;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next_value = [&](const char* flag) -> std::string {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << flag << "\n";
        std::exit(1);
      }
      return argv[++i];
    };

    if (arg == "--name") {
      config.name = next_value("--name");
      have_name = true;
    } else if (arg == "--port") {
      if (!parse_port(next_value("--port"), config.port)) {
        std::cerr << "invalid --port\n";
        return 1;
      }
    } else if (arg == "--peers") {
      std::string error;
      auto seeds = parse_seeds(next_value("--peers"), error);
      if (!error.empty()) {
        std::cerr << error << "\n";
        return 1;
      }
      config.seeds.insert(config.seeds.end(), seeds.begin(), seeds.end());
    } else if (arg == "--no-color") {
      no_color = true;
    } else if (arg == "--help" || arg == "-h") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "unknown option: " << arg << "\n";
      print_usage(argv[0]);
      return 1;
    }
  }

  if (!have_name || config.name.empty()) {
    std::cerr << "--name is required\n";
    print_usage(argv[0]);
    return 1;
  }

  bool color = !no_color && stdout_is_tty();
  if (color) color = enable_virtual_terminal();
  Printer printer(color, stdin_is_tty());
  MeshNode node(config);

  try {
    node.on_peers = [&printer](const std::vector<PeerInfo>& peers) {
      printer.line(kCyan, format_peers(peers), true);
    };
    node.on_peer_offline = [&printer](const std::string& name) {
      printer.line(kYellow, "[offline] " + name, true);
    };
    node.on_message = [&printer, self = node.name()](const std::string& from,
                                                    const std::string& text,
                                                    std::uint64_t hops) {
      std::string line = "[" + self + "] " + from + ": " + text;
      if (hops > 0) line += " (via " + std::to_string(hops) + " relays)";
      printer.line(kGreen, line, true);
    };
    node.on_relay = [&printer](const RelayReport& report) {
      std::string line = "[RELAY] received " + std::to_string(report.received_bytes) +
                         " bytes from " + report.previous + " -> next " + report.next_name +
                         " (" + report.next_endpoint.to_string() + ") | forwarded " +
                         hex_encode(report.forwarded);
      printer.line(kYellow, line, true);
    };
    node.on_packet = [&printer](std::size_t bytes, const Bytes& payload) {
      printer.line(kGray, "  [packet] rx " + std::to_string(bytes) + "B " +
                              hex_encode(payload),
                   true);
    };
    node.on_notice = [&printer](const std::string& text) {
      printer.line(kYellow, "[note] " + text, true);
    };
    node.on_error = [&printer](const std::string& text) {
      printer.line(kRed, "[error] " + text, true);
    };

    std::string error;
    if (!node.start(error)) {
      printer.line(kRed, "startup failed: " + error);
      return 1;
    }

    printer.line(kCyan, "meshchat  " + node.name() + "  [" + node.short_fingerprint() + "]");
    printer.line(kCyan, "unicast UDP " + std::to_string(node.unicast_port()) +
                            "  discovery UDP " + std::to_string(node.discovery_port()) +
                            "  (broadcast every 2s)");
    printer.line(kGray,
                 "send <name> <message> [--relays N] [--verbose-route] | peers | quit");
    printer.prompt();

    std::string line;
    bool quit = false;
    while (!quit && std::getline(std::cin, line)) {
      const std::string trimmed = trim(line);
      if (trimmed.empty()) {
        printer.prompt();
        continue;
      }
      if (trimmed == "quit" || trimmed == "exit") {
        printer.line(kCyan, "bye");
        break;
      }
      if (trimmed == "peers") {
        printer.line(kCyan, format_peers(node.peers()));
        printer.prompt();
        continue;
      }
      if (trimmed == "help" || trimmed == "?") {
        printer.line(kGray,
                     "send <name> <message> [--relays N] [--verbose-route] | peers | quit");
        printer.prompt();
        continue;
      }
      if (trimmed == "send" || trimmed.rfind("send ", 0) != 0) {
        printer.line(kRed, "unknown command; use send, peers, help or quit");
        printer.prompt();
        continue;
      }

      const SendCommand command = parse_send(trimmed.substr(5));
      if (!command.error.empty()) {
        printer.line(kRed, command.error);
        printer.prompt();
        continue;
      }
      const auto outcome = node.send_message(command.target, command.message, command.relays);
      if (!outcome.ok) {
        printer.line(kRed, "[not sent] " + outcome.error);
        printer.prompt();
        continue;
      }
      if (outcome.direct) {
        printer.line(kCyan, "[sent] to " + outcome.target + " (direct)");
      } else {
        printer.line(kCyan, "[sent] to " + outcome.target + " via " +
                                std::to_string(outcome.relays) + " relays");
      }
      if (command.verbose) printer.line(kCyan, "[route] " + outcome.route);
      if (!outcome.note.empty()) printer.line(kYellow, "[note] " + outcome.note);
      printer.prompt();
    }

    node.stop();
    return 0;
  } catch (const std::exception& e) {
    printer.line(kRed, std::string("fatal: ") + e.what());
    node.stop();
    return 1;
  }
}
