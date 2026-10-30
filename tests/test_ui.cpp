#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ui/colors.h"
#include "ui/commands.h"
#include "ui/events.h"
#include "ui/renderer.h"

#if defined(ERROR)
#undef ERROR
#endif

namespace {

using namespace jn::ui;

constexpr const char* kArrow = "\xE2\x86\x92";
constexpr const char* kEllipsis = "\xE2\x80\xA6";
constexpr const char* kEmDash = "\xE2\x80\x94";

int g_failures = 0;

void check(bool condition, const char* expression, int line) {
  if (condition) return;
  std::cerr << "line " << line << ": FAILED " << expression << "\n";
  ++g_failures;
}

#define CHECK(expression) check((expression), #expression, __LINE__)

std::string time_text(std::chrono::system_clock::time_point ts) {
  const std::time_t when = std::chrono::system_clock::to_time_t(ts);
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &when);
#else
  localtime_r(&when, &local);
#endif
  char buffer[16]{};
  std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &local);
  return buffer;
}

std::string render_event(const UIEvent& event, bool color = false, bool show_route = true,
                         bool full_hex = false) {
  std::ostringstream out;
  Renderer renderer(out, color, 200);
  renderer.set_show_route(show_route);
  renderer.set_full_hex(full_hex);
  renderer.emit(event);
  return out.str();
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

void test_parser() {
  Command command = parse_command("/send Bob hi");
  CHECK(command.kind == CommandKind::Send);
  CHECK(command.name == "Bob");
  CHECK(command.message == "hi");
  CHECK(!command.relays_set);
  CHECK(command.error.empty());

  command = parse_command("/send Bob --relays 2 hello through the mesh");
  CHECK(command.kind == CommandKind::Send);
  CHECK(command.name == "Bob");
  CHECK(command.message == "hello through the mesh");
  CHECK(command.relays_set);
  CHECK(command.relays == 2);
  CHECK(command.error.empty());

  command = parse_command("/send Bob hello --relays 2 through the mesh");
  CHECK(command.message == "hello through the mesh");
  CHECK(command.relays == 2);

  command = parse_command("/send Bob --relays");
  CHECK(!command.error.empty());
  command = parse_command("/send Bob --relays 0 hi");
  CHECK(!command.error.empty());
  command = parse_command("/send Bob");
  CHECK(!command.error.empty());
  command = parse_command("/send --relays 2 Bob hi");
  CHECK(!command.error.empty());

  command = parse_command("/route on");
  CHECK(command.kind == CommandKind::Route);
  CHECK(command.name == "on");
  command = parse_command("/route sideways");
  CHECK(!command.error.empty());
  command = parse_command("/hex off");
  CHECK(command.kind == CommandKind::Hex);
  CHECK(command.name == "off");

  command = parse_command("hello there");
  CHECK(command.kind == CommandKind::BareText);
  CHECK(command.message == "hello there");

  command = parse_command("/foo bar");
  CHECK(command.kind == CommandKind::Unknown);
  CHECK(command.name == "/foo");

  CHECK(parse_command("/help").kind == CommandKind::Help);
  CHECK(parse_command("/peers").kind == CommandKind::Peers);
  CHECK(parse_command("/relays").kind == CommandKind::Relays);
  CHECK(parse_command("/status").kind == CommandKind::Status);
  CHECK(parse_command("/clear").kind == CommandKind::Clear);
  CHECK(parse_command("/quit").kind == CommandKind::Quit);
  CHECK(parse_command("   ").kind == CommandKind::None);

  const std::string help = help_text();
  CHECK(contains(help, "/send <name> --relays <N> <msg>"));
  CHECK(contains(help, "/quit"));
}

void test_queues() {
  EventQueue events;
  CHECK(events.empty());
  UIEvent first;
  first.type = EventType::SYSTEM;
  first.sys_msg = "one";
  UIEvent second;
  second.type = EventType::ERROR;
  second.error_msg = "two";
  events.push(first);
  events.push(second);
  CHECK(!events.empty());
  const std::vector<UIEvent> drained = events.drain();
  CHECK(drained.size() == 2);
  CHECK(drained[0].sys_msg == "one");
  CHECK(drained[1].error_msg == "two");
  CHECK(events.empty());

  CommandQueue commands;
  Command command;
  command.kind = CommandKind::Peers;
  commands.push(command);
  CHECK(!commands.empty());
  const std::vector<Command> parsed = commands.drain();
  CHECK(parsed.size() == 1);
  CHECK(parsed[0].kind == CommandKind::Peers);
  CHECK(commands.empty());
}

void test_renderer() {
  const auto ts = std::chrono::system_clock::from_time_t(1700000000);
  const std::string clock = time_text(ts);

  UIEvent event;
  event.ts = ts;
  event.type = EventType::SYSTEM;
  event.sys_msg = "hello";
  CHECK(render_event(event).rfind("[" + clock + "] [SYS ] hello", 0) == 0);

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::PEER_JOINED;
  event.from = "Bob";
  event.fingerprint = std::string("9c11") + kEllipsis + "d4e2";
  event.sys_msg = "192.168.1.12:9002";
  CHECK(contains(render_event(event),
                 "Bob joined (fp 9c11" + std::string(kEllipsis) +
                     "d4e2) at 192.168.1.12:9002"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::PEER_LEFT;
  event.from = "Carol";
  event.sys_msg = "after 3m12s";
  CHECK(contains(render_event(event), "Carol left after 3m12s"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::MESSAGE_SENT;
  event.to = "Bob";
  event.plaintext = "hi";
  event.route = std::string("Relay1 ") + kArrow + " Relay2";
  CHECK(contains(render_event(event),
                 "You " + std::string(kArrow) + " Bob: hi [route: Relay1 " + kArrow +
                     " Relay2]"));
  CHECK(!contains(render_event(event, false, false), "[route:"));
  CHECK(!contains(render_event(event, false, false), "[direct]"));

  event.route.clear();
  CHECK(contains(render_event(event), "You " + std::string(kArrow) + " Bob: hi [direct]"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::MESSAGE_RECEIVED;
  event.from = "Bob";
  event.plaintext = "hi";
  CHECK(contains(render_event(event), "Bob " + std::string(kArrow) + " You: hi"));

  const std::string payload = "a3f2be91c4d5e6f7a8b9c0d1e2f3a4b5";
  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::RELAY_FORWARDED;
  event.from = "Relay1";
  event.to = "Relay2";
  event.size_bytes = 96;
  event.payload_hex = payload;
  const std::string hop = render_event(event);
  CHECK(contains(hop, "Relay1 forwards 96B " + std::string(kArrow) +
                          " Relay2  ct=a3f2be91c4d5e6f7" + kEllipsis));
  CHECK(!contains(hop, payload.substr(16, 4)));

  const std::string full = render_event(event, false, true, true);
  CHECK(!contains(full, kEllipsis));
  CHECK(contains(full, "ct=a3f2be91"));

  const std::string colored = render_event(event, true);
  CHECK(contains(colored, "\033[33m"));
  CHECK(contains(colored, "\033[35m"));
  CHECK(contains(colored, "\033[2;37m"));
  CHECK(contains(colored, "\033[0m"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::ERROR;
  event.error_msg = "send failed: peer 'Dave' not online " + std::string(kEmDash) + " /peers to list";
  CHECK(contains(render_event(event), "[ERR ] send failed: peer 'Dave' not online " + std::string(kEmDash) + " /peers to list"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::STATUS_UPDATE;
  event.sys_msg = "peers=4 relays=3";
  CHECK(contains(render_event(event), "[STAT] peers=4 relays=3"));

  event = UIEvent{};
  event.ts = ts;
  event.type = EventType::MESSAGE_RECEIVED;
  event.from = "Bob";
  event.plaintext = "one\ntwo";
  const std::string multiline = render_event(event);
  const std::size_t break_at = multiline.find('\n');
  CHECK(break_at != std::string::npos);
  CHECK(break_at + 10 <= multiline.size());
  CHECK(multiline.compare(break_at + 1, 9, std::string(9, ' ')) == 0);
  CHECK(contains(multiline, "two"));
}

void test_null_ui() {
  std::ostringstream captured;
  std::streambuf* previous = std::cerr.rdbuf(captured.rdbuf());

  NullUI null_ui;
  UIEvent event;
  event.type = EventType::SYSTEM;
  event.sys_msg = "hidden";
  null_ui.emit(event);

  event = UIEvent{};
  event.type = EventType::RELAY_FORWARDED;
  event.from = "Relay1";
  event.to = "Bob";
  event.size_bytes = 96;
  event.payload_hex = "0011223344556677";
  null_ui.emit(event);

  event = UIEvent{};
  event.type = EventType::ERROR;
  event.error_msg = "visible";
  null_ui.emit(event);
  null_ui.flush();

  std::cerr.rdbuf(previous);
  const std::string output = captured.str();
  CHECK(contains(output, "[HOP ]"));
  CHECK(contains(output, "[ERR ]"));
  CHECK(!contains(output, "[SYS ]"));
  CHECK(!contains(output, "hidden"));
  CHECK(!contains(output, "\033["));
}

void test_colors() {
  CHECK(std::string(ansi::kSys) == "\033[90m");
  CHECK(std::string(ansi::kPeer) == "\033[36m");
  CHECK(std::string(ansi::kSend) == "\033[32m");
  CHECK(std::string(ansi::kRecv) == "\033[1;32m");
  CHECK(std::string(ansi::kHop) == "\033[33m");
  CHECK(std::string(ansi::kErr) == "\033[1;31m");
  CHECK(std::string(ansi::kHexDim) == "\033[2;37m");
  CHECK(std::string(ansi::kRoute) == "\033[35m");
}

void run() {
  test_parser();
  test_queues();
  test_renderer();
  test_null_ui();
  test_colors();
}

}  // namespace

int main() {
  run();
  if (g_failures != 0) {
    std::cerr << g_failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "ok\n";
  return 0;
}
