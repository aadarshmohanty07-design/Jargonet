#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include "ui/renderer.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ui/colors.h"

namespace jn::ui {
namespace {

constexpr const char* kArrow = "\xE2\x86\x92";
constexpr const char* kEllipsis = "\xE2\x80\xA6";

enum class Ink { Plain, Sys, Peer, Send, Recv, Hop, Err, Hex, Route };

struct Span {
  std::string text;
  Ink ink = Ink::Plain;
};

enum class UnitKind { Word, Space, Newline };

struct Unit {
  std::string text;
  Ink ink = Ink::Plain;
  int width = 0;
  UnitKind kind = UnitKind::Word;
};

const char* ink_code(Ink ink) {
  switch (ink) {
    case Ink::Sys:
      return ansi::kSys;
    case Ink::Peer:
      return ansi::kPeer;
    case Ink::Send:
      return ansi::kSend;
    case Ink::Recv:
      return ansi::kRecv;
    case Ink::Hop:
      return ansi::kHop;
    case Ink::Err:
      return ansi::kErr;
    case Ink::Hex:
      return ansi::kHexDim;
    case Ink::Route:
      return ansi::kRoute;
    case Ink::Plain:
      return nullptr;
  }
  return nullptr;
}

std::string paint(const std::string& text, Ink ink, bool color) {
  const char* code = color ? ink_code(ink) : nullptr;
  if (code == nullptr || text.empty()) return text;
  return std::string(code) + text + ansi::kReset;
}

const char* tag_for(EventType type) {
  switch (type) {
    case EventType::PEER_JOINED:
    case EventType::PEER_LEFT:
      return "[PEER]";
    case EventType::MESSAGE_SENT:
      return "[SEND]";
    case EventType::MESSAGE_RECEIVED:
      return "[RECV]";
    case EventType::RELAY_RECEIVED:
    case EventType::RELAY_FORWARDED:
      return "[HOP ]";
    case EventType::STATUS_UPDATE:
      return "[STAT]";
    case EventType::ERROR:
      return "[ERR ]";
    case EventType::SYSTEM:
    case EventType::ROUTE_STARTED:
    case EventType::ROUTE_COMPLETED:
      return "[SYS ]";
  }
  return "[SYS ]";
}

Ink ink_for(EventType type) {
  switch (type) {
    case EventType::PEER_JOINED:
    case EventType::PEER_LEFT:
      return Ink::Peer;
    case EventType::MESSAGE_SENT:
      return Ink::Send;
    case EventType::MESSAGE_RECEIVED:
      return Ink::Recv;
    case EventType::RELAY_RECEIVED:
    case EventType::RELAY_FORWARDED:
      return Ink::Hop;
    case EventType::ERROR:
      return Ink::Err;
    case EventType::SYSTEM:
    case EventType::ROUTE_STARTED:
    case EventType::ROUTE_COMPLETED:
    case EventType::STATUS_UPDATE:
      return Ink::Sys;
  }
  return Ink::Sys;
}

std::string sanitize(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (unsigned char c : text) {
    if (c == '\n') {
      out.push_back('\n');
    } else if (c == '\t') {
      out.push_back(' ');
    } else if (c < 0x20 || c == 0x7f) {
      out.push_back('?');
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

std::size_t utf8_len(unsigned char lead) {
  if (lead < 0x80) return 1;
  if ((lead & 0xe0) == 0xc0) return 2;
  if ((lead & 0xf0) == 0xe0) return 3;
  if ((lead & 0xf8) == 0xf0) return 4;
  return 1;
}

std::uint32_t decode_codepoint(const std::string& text, std::size_t offset, std::size_t length) {
  unsigned char lead = static_cast<unsigned char>(text[offset]);
  if (length == 1) return lead;
  std::uint32_t cp = lead & (0x7f >> length);
  for (std::size_t i = 1; i < length && offset + i < text.size(); ++i) {
    cp = (cp << 6) | (static_cast<unsigned char>(text[offset + i]) & 0x3f);
  }
  return cp;
}

int codepoint_width(std::uint32_t cp) {
  if (cp == 0) return 0;
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) return 0;
  if ((cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) ||
      (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) ||
      (cp >= 0xfe30 && cp <= 0xfe6f) || (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) ||
      (cp >= 0x1f900 && cp <= 0x1f9ff) || (cp >= 0x20000 && cp <= 0x3fffd)) {
    return 2;
  }
  return 1;
}

int text_width(const std::string& text) {
  int width = 0;
  for (std::size_t i = 0; i < text.size();) {
    std::size_t length = utf8_len(static_cast<unsigned char>(text[i]));
    if (i + length > text.size()) length = 1;
    width += codepoint_width(decode_codepoint(text, i, length));
    i += length;
  }
  return width;
}

std::string short_fingerprint(const std::string& fingerprint) {
  const std::string clean = sanitize(fingerprint);
  if (clean.size() <= 9 || clean.find(kEllipsis) != std::string::npos) return clean;
  return clean.substr(0, 4) + kEllipsis + clean.substr(clean.size() - 4);
}

std::string format_time(std::chrono::system_clock::time_point ts) {
  const std::time_t when = std::chrono::system_clock::to_time_t(ts);
  std::tm local{};
#ifdef _WIN32
  if (localtime_s(&local, &when) != 0) return "00:00:00";
#else
  if (localtime_r(&when, &local) == nullptr) return "00:00:00";
#endif
  char buffer[16]{};
  if (std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &local) == 0) return "00:00:00";
  return buffer;
}

std::string hex_view(const std::string& payload, bool full) {
  const std::string clean = sanitize(payload);
  if (full || clean.size() <= 16) return clean;
  return clean.substr(0, 16) + kEllipsis;
}

void add_span(std::vector<Span>& spans, std::string text, Ink ink) {
  if (!text.empty()) spans.push_back({std::move(text), ink});
}

void add_text(std::vector<Span>& spans, const std::string& raw, Ink ink) {
  add_span(spans, sanitize(raw), ink);
}

void add_with_route_arrows(std::vector<Span>& spans, const std::string& raw, Ink ink) {
  const std::string text = sanitize(raw);
  std::size_t position = 0;
  while (position < text.size()) {
    const std::size_t arrow = text.find(kArrow, position);
    if (arrow == std::string::npos) {
      add_span(spans, text.substr(position), ink);
      break;
    }
    add_span(spans, text.substr(position, arrow - position), ink);
    add_span(spans, kArrow, Ink::Route);
    position = arrow + 3;
  }
}

std::vector<Span> body_for(const UIEvent& event, bool show_route, bool full_hex) {
  std::vector<Span> spans;
  switch (event.type) {
    case EventType::SYSTEM:
      add_text(spans, event.sys_msg.empty() ? event.plaintext : event.sys_msg, Ink::Sys);
      break;

    case EventType::PEER_JOINED:
      add_text(spans, event.from.empty() ? "peer" : event.from, Ink::Peer);
      add_span(spans, " joined", Ink::Peer);
      if (!event.fingerprint.empty()) {
        add_span(spans, " (fp ", Ink::Peer);
        add_span(spans, short_fingerprint(event.fingerprint), Ink::Peer);
        add_span(spans, ")", Ink::Peer);
      }
      if (!event.sys_msg.empty()) {
        add_span(spans, " at ", Ink::Peer);
        add_text(spans, event.sys_msg, Ink::Peer);
      }
      break;

    case EventType::PEER_LEFT:
      add_text(spans, event.from.empty() ? "peer" : event.from, Ink::Peer);
      add_span(spans, " left", Ink::Peer);
      if (!event.sys_msg.empty()) {
        add_span(spans, " ", Ink::Peer);
        add_text(spans, event.sys_msg, Ink::Peer);
      }
      break;

    case EventType::MESSAGE_SENT:
      add_span(spans, "You ", Ink::Send);
      add_span(spans, kArrow, Ink::Route);
      add_span(spans, " ", Ink::Send);
      add_text(spans, event.to, Ink::Send);
      add_span(spans, ": ", Ink::Send);
      add_text(spans, event.plaintext, Ink::Send);
      if (show_route) {
        if (event.route.empty()) {
          add_span(spans, " [direct]", Ink::Send);
        } else {
          add_span(spans, " [route: ", Ink::Send);
          add_with_route_arrows(spans, event.route, Ink::Send);
          add_span(spans, "]", Ink::Send);
        }
      }
      break;

    case EventType::MESSAGE_RECEIVED:
      add_text(spans, event.from.empty() ? "peer" : event.from, Ink::Recv);
      add_span(spans, " ", Ink::Recv);
      add_span(spans, kArrow, Ink::Route);
      add_span(spans, " You: ", Ink::Recv);
      add_text(spans, event.plaintext, Ink::Recv);
      break;

    case EventType::RELAY_RECEIVED:
      add_text(spans, event.from.empty() ? "relay" : event.from, Ink::Hop);
      add_span(spans, " received " + std::to_string(event.size_bytes) + "B ", Ink::Hop);
      if (!event.payload_hex.empty()) {
        add_span(spans, "ct=", Ink::Hop);
        add_span(spans, hex_view(event.payload_hex, full_hex), Ink::Hex);
      }
      break;

    case EventType::RELAY_FORWARDED: {
      add_text(spans, event.from.empty() ? "relay" : event.from, Ink::Hop);
      add_span(spans, " forwards " + std::to_string(event.size_bytes) + "B ", Ink::Hop);
      add_span(spans, kArrow, Ink::Route);
      add_span(spans, " ", Ink::Hop);
      const std::string target = sanitize(event.to.empty() ? "next hop" : event.to);
      add_span(spans, target, Ink::Hop);
      const int padding = std::max(1, 8 - text_width(target));
      add_span(spans, std::string(static_cast<std::size_t>(padding), ' '), Ink::Hop);
      if (!event.payload_hex.empty()) {
        add_span(spans, "ct=", Ink::Hop);
        add_span(spans, hex_view(event.payload_hex, full_hex), Ink::Hex);
      }
      break;
    }

    case EventType::ROUTE_STARTED:
    case EventType::ROUTE_COMPLETED:
      if (!event.sys_msg.empty()) {
        add_text(spans, event.sys_msg, Ink::Sys);
      } else {
        add_span(spans, event.type == EventType::ROUTE_STARTED ? "route started" : "route completed",
                 Ink::Sys);
        if (!event.route.empty()) {
          add_span(spans, ": ", Ink::Sys);
          add_with_route_arrows(spans, event.route, Ink::Sys);
        }
      }
      break;

    case EventType::STATUS_UPDATE:
      add_text(spans, event.sys_msg.empty() ? "status update" : event.sys_msg, Ink::Sys);
      break;

    case EventType::ERROR:
      add_text(spans, event.error_msg.empty() ? "unknown error" : event.error_msg, Ink::Err);
      break;
  }
  return spans;
}

std::vector<Unit> tokenize(const std::vector<Span>& spans) {
  std::vector<Unit> units;
  for (const Span& span : spans) {
    std::string word;
    int word_width = 0;
    auto flush_word = [&] {
      if (word.empty()) return;
      units.push_back({word, span.ink, word_width, UnitKind::Word});
      word.clear();
      word_width = 0;
    };

    for (std::size_t i = 0; i < span.text.size();) {
      const unsigned char c = static_cast<unsigned char>(span.text[i]);
      if (c == '\n') {
        flush_word();
        units.push_back({"", span.ink, 0, UnitKind::Newline});
        ++i;
      } else if (c == ' ') {
        flush_word();
        if (!units.empty() && units.back().kind == UnitKind::Space && units.back().ink == span.ink) {
          units.back().text.push_back(' ');
          ++units.back().width;
        } else {
          units.push_back({" ", span.ink, 1, UnitKind::Space});
        }
        ++i;
      } else {
        std::size_t length = utf8_len(c);
        if (i + length > span.text.size()) length = 1;
        word.append(span.text, i, length);
        word_width += codepoint_width(decode_codepoint(span.text, i, length));
        i += length;
      }
    }
    flush_word();
  }
  return units;
}

std::pair<Unit, Unit> split_word(const Unit& unit, int max_width) {
  std::size_t offset = 0;
  int head_width = 0;
  std::string head;
  while (offset < unit.text.size()) {
    std::size_t length = utf8_len(static_cast<unsigned char>(unit.text[offset]));
    if (offset + length > unit.text.size()) length = 1;
    const int width = codepoint_width(decode_codepoint(unit.text, offset, length));
    if (!head.empty() && head_width + width > max_width) break;
    head.append(unit.text, offset, length);
    head_width += width;
    offset += length;
    if (head_width >= max_width) break;
  }
  if (head.empty()) {
    std::size_t length = utf8_len(static_cast<unsigned char>(unit.text[0]));
    if (length > unit.text.size()) length = unit.text.size();
    head = unit.text.substr(0, length);
    head_width = text_width(head);
    offset = length;
  }
  const std::string tail = unit.text.substr(offset);
  return {Unit{head, unit.ink, head_width, UnitKind::Word},
          Unit{tail, unit.ink, text_width(tail), UnitKind::Word}};
}

std::vector<std::vector<Unit>> wrap_units(const std::vector<Unit>& units, int first_limit,
                                          int cont_limit) {
  first_limit = std::max(10, first_limit);
  cont_limit = std::max(10, cont_limit);

  std::vector<std::vector<Unit>> lines;
  std::vector<Unit> current;
  std::vector<Unit> pending_spaces;
  int line_width = 0;
  int pending_width = 0;
  int limit = first_limit;
  bool has_word = false;

  auto trim_trailing = [&] {
    while (!current.empty() && current.back().kind == UnitKind::Space) {
      line_width -= current.back().width;
      current.pop_back();
    }
  };
  auto flush_line = [&](bool force) {
    trim_trailing();
    if (!current.empty() || force) lines.push_back(current);
    current.clear();
    line_width = 0;
    pending_width = 0;
    has_word = false;
    limit = cont_limit;
  };

  for (const Unit& unit : units) {
    if (unit.kind == UnitKind::Newline) {
      pending_spaces.clear();
      flush_line(true);
      continue;
    }
    if (unit.kind == UnitKind::Space) {
      if (!has_word) continue;
      pending_spaces.push_back(unit);
      pending_width += unit.width;
      continue;
    }

    if (has_word && line_width + pending_width + unit.width > limit) {
      pending_spaces.clear();
      flush_line(false);
    }
    if (has_word) {
      for (const Unit& space : pending_spaces) {
        current.push_back(space);
        line_width += space.width;
      }
    }
    pending_spaces.clear();
    pending_width = 0;

    Unit rest = unit;
    while (!rest.text.empty()) {
      if (line_width + rest.width <= limit) {
        current.push_back(rest);
        line_width += rest.width;
        has_word = true;
        break;
      }
      const int room = limit - line_width;
      if (room <= 0) {
        flush_line(false);
        continue;
      }
      auto split = split_word(rest, room);
      current.push_back(split.first);
      line_width += split.first.width;
      has_word = true;
      rest = std::move(split.second);
      if (rest.text.empty()) break;
      flush_line(false);
    }
  }

  pending_spaces.clear();
  if (!current.empty() || lines.empty()) {
    trim_trailing();
    lines.push_back(current);
  }
  return lines;
}

}  // namespace

bool stdout_supports_color() {
  if (std::getenv("NO_COLOR") != nullptr) return false;
#ifdef _WIN32
  HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &mode) != 0) {
#ifdef ENABLE_VIRTUAL_TERMINAL_PROCESSING
    if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 &&
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                                   ENABLE_PROCESSED_OUTPUT) == 0) {
      return false;
    }
#endif
    return true;
  }
  if (_isatty(_fileno(stdout)) != 0) return true;
  const char* term = std::getenv("TERM");
  return term != nullptr && std::string(term) != "dumb";
#else
  if (::isatty(STDOUT_FILENO) == 0) return false;
  const char* term = std::getenv("TERM");
  return term == nullptr || std::string(term) != "dumb";
#endif
}

int terminal_width() {
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info) != 0) {
    const int width = static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1);
    if (width > 0) return width;
  }
#else
  winsize size{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0) {
    return static_cast<int>(size.ws_col);
  }
#endif
  if (const char* columns = std::getenv("COLUMNS")) {
    char* end = nullptr;
    const long value = std::strtol(columns, &end, 10);
    if (end != columns && *end == '\0' && value > 0 && value <= 10000) {
      return static_cast<int>(value);
    }
  }
  return 80;
}

Renderer::Renderer(std::ostream& out, bool color, int width)
    : out_(out), color_(color), width_(width) {}

void Renderer::emit(const UIEvent& event) {
  const std::string line = format(event);
  std::lock_guard<std::mutex> lock(out_mutex_);
  out_ << line << '\n';
  out_.flush();
}

void Renderer::clear() {
  std::lock_guard<std::mutex> lock(out_mutex_);
  out_ << ansi::kClearScreen;
  out_.flush();
}

void Renderer::show_prompt() {
  std::lock_guard<std::mutex> lock(out_mutex_);
  out_ << "> ";
  out_.flush();
}

void Renderer::flush() {
  std::lock_guard<std::mutex> lock(out_mutex_);
  out_.flush();
}

void Renderer::set_show_route(bool enabled) { show_route_.store(enabled); }

void Renderer::set_full_hex(bool enabled) { full_hex_.store(enabled); }

bool Renderer::show_route() const { return show_route_.load(); }

bool Renderer::full_hex() const { return full_hex_.load(); }

std::string Renderer::format(const UIEvent& event) const {
  const bool show_route = show_route_.load();
  const bool full_hex = full_hex_.load();
  const std::vector<Span> spans = body_for(event, show_route, full_hex);
  const std::vector<Unit> units = tokenize(spans);

  int width = width_ > 0 ? width_ : terminal_width();
  if (width < 30) width = 30;
  const std::vector<std::vector<Unit>> lines =
      wrap_units(units, width - 18, width - 9);

  const std::string timestamp = format_time(event.ts);
  const char* tag = tag_for(event.type);
  const Ink tag_ink = ink_for(event.type);

  std::string out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i > 0) out.push_back('\n');
    if (i == 0) {
      out += paint("[" + timestamp + "]", Ink::Sys, color_);
      out.push_back(' ');
      out += paint(tag, tag_ink, color_);
      out.push_back(' ');
    } else {
      out.append(9, ' ');
    }
    for (const Unit& unit : lines[i]) {
      if (unit.kind == UnitKind::Space) {
        out += unit.text;
      } else {
        out += paint(unit.text, unit.ink, color_);
      }
    }
  }
  return out;
}

NullUI::NullUI() : sink_(std::cerr, false) {}

void NullUI::emit(const UIEvent& event) {
  if (event.type != EventType::RELAY_RECEIVED && event.type != EventType::RELAY_FORWARDED &&
      event.type != EventType::ERROR) {
    return;
  }
  sink_.emit(event);
}

void NullUI::flush() { sink_.flush(); }

}  // namespace jn::ui
