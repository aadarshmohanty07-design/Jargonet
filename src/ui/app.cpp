#include "ui/app.h"

#include <chrono>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "ui/colors.h"

#if defined(ERROR)
#undef ERROR
#endif

namespace jn::ui {
namespace {

constexpr const char* kEmDash = "\xE2\x80\x94";
constexpr const char* kMidDot = "\xC2\xB7";
constexpr const char* kTopLeft = "\xE2\x94\x8C";
constexpr const char* kTopRight = "\xE2\x94\x90";
constexpr const char* kBottomLeft = "\xE2\x94\x94";
constexpr const char* kBottomRight = "\xE2\x94\x98";
constexpr const char* kHorizontal = "\xE2\x94\x80";
constexpr const char* kVertical = "\xE2\x94\x82";

std::string repeat(const char* glyph, int count) {
  std::string out;
  for (int i = 0; i < count; ++i) out += glyph;
  return out;
}

int codepoints(const std::string& text) {
  int count = 0;
  for (std::size_t i = 0; i < text.size();) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    std::size_t length = 1;
    if ((c & 0xe0) == 0xc0) {
      length = 2;
    } else if ((c & 0xf0) == 0xe0) {
      length = 3;
    } else if ((c & 0xf8) == 0xf0) {
      length = 4;
    }
    if (i + length > text.size()) length = 1;
    i += length;
    ++count;
  }
  return count;
}

std::string banner_row(const std::string& content, int inner_width) {
  const int width = codepoints(content);
  return std::string(kVertical) + content +
         std::string(static_cast<std::size_t>(width < inner_width ? inner_width - width : 0), ' ') +
         kVertical;
}

std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (char c : text) {
    if (c == '\n') {
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty()) lines.push_back(current);
  return lines;
}

}  // namespace

App::App(EventQueue& events, CommandQueue& commands, IRenderer& renderer)
    : events_(events), commands_(commands), renderer_(renderer) {}

App::~App() {
  stop();
  if (render_thread_.joinable()) render_thread_.join();
}

void App::stop() { running_.store(false); }

int App::run(const StartupInfo& info) {
  print_banner();

  UIEvent started;
  started.type = EventType::SYSTEM;
  started.sys_msg = "meshchat v" + info.version + " started " + kEmDash + " " + info.name +
                    " (fp " + info.fingerprint + ") on " + info.listen_ip + ":" +
                    std::to_string(info.port);
  renderer_.emit(started);

  UIEvent listening;
  listening.type = EventType::SYSTEM;
  listening.sys_msg = "discovery listening on UDP :" + std::to_string(info.discovery_port) +
                      ", mesh listening on UDP :" + std::to_string(info.port);
  renderer_.emit(listening);
  renderer_.flush();

  render_thread_ = std::thread(&App::render_loop, this);
  renderer_.show_prompt();

  std::string line;
  while (running_.load()) {
    if (!std::getline(std::cin, line)) {
      running_.store(false);
      break;
    }
    handle_line(line);
    if (running_.load()) renderer_.show_prompt();
  }

  running_.store(false);
  if (!quit_queued_) {
    Command quit;
    quit.kind = CommandKind::Quit;
    commands_.push(std::move(quit));
  }
  if (render_thread_.joinable()) render_thread_.join();

  UIEvent goodbye;
  goodbye.type = EventType::SYSTEM;
  goodbye.sys_msg = "goodbye";
  renderer_.emit(goodbye);
  renderer_.flush();
  return 0;
}

void App::render_loop() {
  while (running_.load()) {
    std::vector<UIEvent> batch = events_.drain();
    if (!batch.empty()) {
      for (const UIEvent& event : batch) {
        observe(event);
        renderer_.emit(event);
      }
      renderer_.flush();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  std::vector<UIEvent> tail = events_.drain();
  for (const UIEvent& event : tail) {
    observe(event);
    renderer_.emit(event);
  }
  if (!tail.empty()) renderer_.flush();
}

void App::observe(const UIEvent& event) {
  const std::string* peer = nullptr;
  if (event.type == EventType::MESSAGE_SENT) {
    peer = &event.to;
  } else if (event.type == EventType::MESSAGE_RECEIVED) {
    peer = &event.from;
  }
  if (peer == nullptr || peer->empty()) return;
  std::lock_guard<std::mutex> lock(conversations_mutex_);
  conversations_.insert(*peer);
}

void App::handle_line(const std::string& line) {
  Command command = parse_command(line);
  switch (command.kind) {
    case CommandKind::None:
      break;

    case CommandKind::Help:
      for (const std::string& help_line : split_lines(help_text())) {
        if (!help_line.empty()) enqueue_system(help_line);
      }
      break;

    case CommandKind::Peers:
    case CommandKind::Relays:
    case CommandKind::Status:
      commands_.push(std::move(command));
      break;

    case CommandKind::Send:
      if (!command.error.empty()) {
        enqueue_error(command.error);
        break;
      }
      commands_.push(std::move(command));
      break;

    case CommandKind::BareText: {
      std::string peer;
      std::size_t count = 0;
      {
        std::lock_guard<std::mutex> lock(conversations_mutex_);
        count = conversations_.size();
        if (count == 1) peer = *conversations_.begin();
      }
      if (count == 1) {
        Command send;
        send.kind = CommandKind::Send;
        send.name = std::move(peer);
        send.message = command.message;
        commands_.push(std::move(send));
      } else if (count == 0) {
        enqueue_error("no conversation selected \xE2\x80\x94 use /send <name> <msg>");
      } else {
        enqueue_error("more than one conversation \xE2\x80\x94 use /send <name> <msg>");
      }
      break;
    }

    case CommandKind::Route:
      if (!command.error.empty()) {
        enqueue_error(command.error);
      } else {
        const bool enabled = command.name == "on";
        renderer_.set_show_route(enabled);
        enqueue_system(std::string("route display ") + (enabled ? "on" : "off"));
      }
      break;

    case CommandKind::Hex:
      if (!command.error.empty()) {
        enqueue_error(command.error);
      } else {
        const bool enabled = command.name == "on";
        renderer_.set_full_hex(enabled);
        enqueue_system(std::string("full hex ") + (enabled ? "on" : "off"));
      }
      break;

    case CommandKind::Clear:
      renderer_.clear();
      break;

    case CommandKind::Quit:
      commands_.push(std::move(command));
      quit_queued_ = true;
      running_.store(false);
      break;

    case CommandKind::Unknown:
      enqueue_error("unknown command: " + command.name + " \xE2\x80\x94 try /help");
      break;
  }
}

void App::enqueue_system(const std::string& text) {
  UIEvent event;
  event.type = EventType::SYSTEM;
  event.sys_msg = text;
  events_.push(std::move(event));
}

void App::enqueue_error(const std::string& text) {
  UIEvent event;
  event.type = EventType::ERROR;
  event.error_msg = text;
  events_.push(std::move(event));
}

void App::print_banner() const {
  const bool color = stdout_supports_color();
  std::string content1 = "  meshchat ";
  content1 += kEmDash;
  content1 += " private LAN messenger";
  std::string content2 = "  onion-routed ";
  content2 += kMidDot;
  content2 += " end-to-end encrypted";

  const int inner_width = 45;
  const std::string top =
      std::string(kTopLeft) + repeat(kHorizontal, inner_width) + kTopRight;
  const std::string bottom =
      std::string(kBottomLeft) + repeat(kHorizontal, inner_width) + kBottomRight;

  std::cout << '\n';
  if (color) std::cout << ansi::kBanner;
  std::cout << top << '\n'
            << banner_row(content1, inner_width) << '\n'
            << banner_row(content2, inner_width) << '\n'
            << bottom << '\n';
  if (color) std::cout << ansi::kReset;
  std::cout << '\n' << std::flush;
}

}  // namespace jn::ui
