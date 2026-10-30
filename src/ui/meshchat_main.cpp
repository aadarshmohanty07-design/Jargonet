#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <signal.h>
#endif

#include "ui/app.h"
#include "ui/commands.h"
#include "ui/events.h"
#include "ui/renderer.h"

namespace {

using namespace jn::ui;

constexpr const char* kEmDash = "\xE2\x80\x94";
constexpr const char* kEllipsis = "\xE2\x80\xA6";
constexpr const char* kArrowSpaced = " \xE2\x86\x92 ";

std::atomic<App*> g_app{nullptr};

void on_interrupt(int) {
  App* app = g_app.load(std::memory_order_relaxed);
  if (app != nullptr) app->stop();
}

std::string trim(std::string text) {
  std::size_t begin = 0;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
  std::size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
  return text.substr(begin, end - begin);
}

bool parse_port(const std::string& text, int& port) {
  try {
    std::size_t used = 0;
    const int value = std::stoi(text, &used);
    if (used != text.size() || value <= 0 || value > 65535) return false;
    port = value;
    return true;
  } catch (...) {
    return false;
  }
}

std::string fingerprint_for(const std::string& name) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (unsigned char c : name) {
    hash ^= c;
    hash *= 1099511628211ULL;
  }
  const std::uint64_t other = hash * 6364136223846793005ULL + 1442695040888963407ULL;
  char first[8]{};
  char last[8]{};
  std::snprintf(first, sizeof(first), "%04llx",
                static_cast<unsigned long long>(hash & 0xffff));
  std::snprintf(last, sizeof(last), "%04llx",
                static_cast<unsigned long long>((other >> 16) & 0xffff));
  return std::string(first) + kEllipsis + last;
}

struct DemoPeer {
  std::string name;
  std::string fingerprint;
  std::string endpoint;
  bool relay = true;
  std::string online_for;
};

std::vector<DemoPeer> make_peers() {
  return {
      {"Bob", std::string("9c11") + kEllipsis + "d4e2", "192.168.1.12:9002", false, "14s"},
      {"Carol", std::string("5d7a") + kEllipsis + "11c0", "192.168.1.13:9003", true, "11s"},
      {"Dave", std::string("77e0") + kEllipsis + "4b21", "192.168.1.14:9004", true, "8s"},
      {"Erin", std::string("2b8f") + kEllipsis + "6c93", "192.168.1.15:9005", true, "5s"},
  };
}

struct DemoState {
  EventQueue& events;
  CommandQueue& commands;
  std::vector<DemoPeer> peers;
  std::string me;
  std::string fingerprint;
  int port = 9001;
  std::atomic<bool> running{true};
};

bool iequals(const std::string& left, const std::string& right) {
  if (left.size() != right.size()) return false;
  for (std::size_t i = 0; i < left.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(left[i])) !=
        std::tolower(static_cast<unsigned char>(right[i]))) {
      return false;
    }
  }
  return true;
}

DemoPeer* find_peer(DemoState& demo, const std::string& name) {
  for (DemoPeer& peer : demo.peers) {
    if (iequals(peer.name, name)) return &peer;
  }
  return nullptr;
}

int relay_count(const DemoState& demo) {
  int count = 0;
  for (const DemoPeer& peer : demo.peers) {
    if (peer.relay) ++count;
  }
  return count;
}

void push_system(EventQueue& events, std::string text) {
  UIEvent event;
  event.type = EventType::SYSTEM;
  event.sys_msg = std::move(text);
  events.push(std::move(event));
}

void push_error(EventQueue& events, std::string text) {
  UIEvent event;
  event.type = EventType::ERROR;
  event.error_msg = std::move(text);
  events.push(std::move(event));
}

void push_status(EventQueue& events, std::string text) {
  UIEvent event;
  event.type = EventType::STATUS_UPDATE;
  event.sys_msg = std::move(text);
  events.push(std::move(event));
}

void push_peer_joined(EventQueue& events, const DemoPeer& peer) {
  UIEvent event;
  event.type = EventType::PEER_JOINED;
  event.from = peer.name;
  event.fingerprint = peer.fingerprint;
  event.sys_msg = peer.endpoint;
  events.push(std::move(event));
}

std::string demo_hex(std::size_t bytes, std::uint64_t seed) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes * 2);
  std::uint64_t state = seed ^ 0x9e3779b97f4a7c15ULL;
  for (std::size_t i = 0; i < bytes * 2; ++i) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    out.push_back(digits[((state * 2685821657736338717ULL) >> 60) & 0xf]);
  }
  return out;
}

std::string join_route(const std::vector<std::string>& route) {
  std::string out;
  for (const std::string& hop : route) {
    if (!out.empty()) out += kArrowSpaced;
    out += hop;
  }
  return out;
}

void list_peers(DemoState& demo) {
  push_system(demo.events, "Online peers:");
  for (const DemoPeer& peer : demo.peers) {
    push_system(demo.events, peer.name + " (" + peer.fingerprint + ") " + peer.endpoint + " " +
                                 kEmDash + " online " + peer.online_for);
  }
}

void list_relays(DemoState& demo) {
  push_system(demo.events, "Relay-eligible peers:");
  for (const DemoPeer& peer : demo.peers) {
    if (!peer.relay) continue;
    push_system(demo.events, peer.name + " (" + peer.fingerprint + ") " + peer.endpoint);
  }
}

void show_status(DemoState& demo) {
  push_system(demo.events, demo.me + " (fp " + demo.fingerprint + ") 0.0.0.0:" +
                               std::to_string(demo.port));
  push_status(demo.events, "peers=" + std::to_string(demo.peers.size()) +
                               " relays=" + std::to_string(relay_count(demo)));
}

void handle_send(DemoState& demo, const Command& command) {
  DemoPeer* peer = find_peer(demo, command.name);
  if (peer == nullptr) {
    push_error(demo.events,
               "send failed: peer '" + command.name + "' not online \xE2\x80\x94 /peers to list");
    return;
  }
  if (command.message.size() > 2048) {
    push_error(demo.events, "message too long (max 2048 bytes)");
    return;
  }

  std::vector<std::string> route;
  if (command.relays_set) {
    std::vector<const DemoPeer*> eligible;
    for (const DemoPeer& candidate : demo.peers) {
      if (candidate.relay && &candidate != peer) eligible.push_back(&candidate);
    }
    if (eligible.empty()) {
      push_error(demo.events, "no relay available \xE2\x80\x94 falling back to direct");
    } else {
      const std::size_t wanted = static_cast<std::size_t>(command.relays);
      const std::size_t used = std::min(wanted, eligible.size());
      if (used < wanted) {
        push_system(demo.events, "only " + std::to_string(used) +
                                     (used == 1 ? " relay" : " relays") + " online \xE2\x80\x94 using " +
                                     std::to_string(used) + "-hop route");
      }
      for (std::size_t i = 0; i < used; ++i) route.push_back(eligible[i]->name);
    }
  }

  UIEvent sent;
  sent.type = EventType::MESSAGE_SENT;
  sent.to = peer->name;
  sent.plaintext = command.message;
  if (!route.empty()) sent.route = join_route(route);
  demo.events.push(sent);

  if (route.empty()) return;

  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  for (std::size_t i = 0; i < route.size(); ++i) {
    UIEvent hop;
    hop.type = EventType::RELAY_FORWARDED;
    hop.from = route[i];
    hop.to = (i + 1 < route.size()) ? route[i + 1] : peer->name;
    hop.size_bytes = 96;
    hop.payload_hex = demo_hex(96, 0x51ed270b + i * 0x9e3779b97f4a7c15ULL);
    demo.events.push(std::move(hop));
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
  }
}

void handle_command(DemoState& demo, const Command& command) {
  switch (command.kind) {
    case CommandKind::Peers:
      list_peers(demo);
      break;
    case CommandKind::Relays:
      list_relays(demo);
      break;
    case CommandKind::Status:
      show_status(demo);
      break;
    case CommandKind::Send:
      handle_send(demo, command);
      break;
    case CommandKind::Quit:
      demo.running.store(false);
      break;
    default:
      break;
  }
}

void run_backend(DemoState& demo) {
  const auto started = std::chrono::steady_clock::now();
  std::size_t joined = 0;
  bool status_sent = false;
  bool hello_sent = false;

  while (demo.running.load()) {
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (joined < demo.peers.size() &&
        elapsed >= std::chrono::milliseconds(150 * static_cast<int>(joined + 1))) {
      push_peer_joined(demo.events, demo.peers[joined]);
      ++joined;
    }
    if (joined == demo.peers.size() && !status_sent && elapsed >= std::chrono::milliseconds(800)) {
      push_status(demo.events, "peers=" + std::to_string(demo.peers.size()) +
                                   " relays=" + std::to_string(relay_count(demo)));
      status_sent = true;
    }
    if (!hello_sent && elapsed >= std::chrono::milliseconds(1500)) {
      UIEvent hello;
      hello.type = EventType::MESSAGE_RECEIVED;
      hello.from = "Bob";
      hello.plaintext = "hi";
      demo.events.push(std::move(hello));
      hello_sent = true;
    }

    std::vector<Command> commands = demo.commands.drain();
    for (const Command& command : commands) {
      if (command.kind == CommandKind::Quit) {
        demo.running.store(false);
        break;
      }
      handle_command(demo, command);
    }
    if (!demo.running.load()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

void print_usage(const char* program) {
  std::cout << "meshchat - terminal frontend for the meshchat event contract\n\n"
            << "Usage:\n"
            << "  " << program << " [--name <name>] [--port <port>]\n\n"
            << "This build runs a local fake backend so the UI can be exercised without\n"
            << "the networking layer. Names are limited to 16 characters.\n";
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
#endif

  std::string name;
  int port = 9001;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--name" && i + 1 < argc) {
      name = argv[++i];
    } else if (arg == "--port" && i + 1 < argc) {
      if (!parse_port(argv[++i], port)) {
        std::cerr << "invalid port\n";
        return 2;
      }
    } else if (arg == "--help" || arg == "-h") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "unknown option: " << arg << "\n";
      print_usage(argv[0]);
      return 2;
    }
  }

  if (name.empty()) {
    std::cout << "Your name: " << std::flush;
    std::getline(std::cin, name);
    name = trim(name);
  }
  if (name.empty() || name.size() > 16) {
    std::cerr << "name must be 1-16 characters\n";
    return 2;
  }

  const bool color = stdout_supports_color();
  EventQueue events;
  CommandQueue commands;
  Renderer renderer(std::cout, color);
  App app(events, commands, renderer);

  StartupInfo info;
  info.version = "0.1";
  info.name = name;
  info.fingerprint = fingerprint_for(name);
  info.listen_ip = "0.0.0.0";
  info.port = port;
  info.discovery_port = 9999;

  DemoState demo{events, commands, make_peers(), name, info.fingerprint, port};
  std::thread backend([&demo] { run_backend(demo); });

  g_app.store(&app);
#ifdef _WIN32
  std::signal(SIGINT, on_interrupt);
#else
  struct sigaction action {};
  action.sa_handler = on_interrupt;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;
  sigaction(SIGINT, &action, nullptr);
#endif

  const int code = app.run(info);
  g_app.store(nullptr);
  demo.running.store(false);
  if (backend.joinable()) backend.join();
  return code;
}
