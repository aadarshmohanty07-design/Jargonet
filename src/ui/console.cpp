#include "ui/console.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

#include "core/crypto.hpp"
#include "core/encoding.hpp"

namespace jn {
namespace {

std::vector<std::string> split_command(const std::string& line) {
  std::vector<std::string> parts;
  std::istringstream stream(line);
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

std::string short_sid(const SessionId& sid) {
  return hex_encode(sid.data(), 8);
}

// Peer-provided text is untrusted terminal input. Keep the stored/sent bytes
// intact but neutralize control characters before rendering them.
std::string display_safe(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char c : value) {
    if (c == '\t') {
      out.push_back(' ');
    } else if (c < 0x20 || c == 0x7f) {
      out.push_back('?');
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

}  // namespace

ConsoleApp::ConsoleApp(NodeConfig config, Identity identity, const std::string& password)
    : node_(std::move(config), std::move(identity), password) {
  install_callbacks();
}

ConsoleApp::~ConsoleApp() {
  quit_ = true;
  if (input_.joinable()) input_.detach();
}

void ConsoleApp::install_callbacks() {
  node_.on_system = [this](const std::string& text) {
    std::cout << "\n[system] " << display_safe(text) << std::endl;
  };
  node_.on_request = [this](const PendingRequestInfo& info) {
    const std::string name = display_safe(info.name);
    std::cout << "\n[request] " << name << " (" << info.fingerprint << ") wants to chat."
              << "  /accept " << name << "   or   /decline " << name << std::endl;
  };
  node_.on_session = [this](const SessionView& view) {
    std::cout << "\n[session] " << display_safe(view.label) << "  sid " << short_sid(view.sid)
              << (view.group ? "  (group)" : "") << std::endl;
    select_session(view);
  };
  node_.on_message = [this](const IncomingMessage& message) {
    const std::string suffix = message.onion ? "  (via onion)" : "";
    const std::string name = display_safe(message.from_name);
    const std::string text = display_safe(message.text);
    if (message.group) {
      std::cout << "\n[" << display_safe(message.session_label) << "] " << name << ": "
                << text << suffix << std::endl;
    } else {
      std::cout << "\n" << name << "> " << text << suffix << std::endl;
    }
  };
}

void ConsoleApp::start_input_thread() {
  input_ = std::thread([this] {
    std::string line;
    while (!quit_) {
      if (!std::getline(std::cin, line)) {
        input_closed_ = true;
        quit_ = true;
        break;
      }
      {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push_back(line);
      }
    }
  });
}

void ConsoleApp::print_prompt() {
  if (!quit_) {
    std::cout << "> " << std::flush;
  }
}

void ConsoleApp::print_help() const {
  std::cout <<
      "\nCommands\n"
      "  /whoami                      show username, fingerprint and invite\n"
      "  /invite                      print your contact invite code\n"
      "  /add <invite>                add a peer from an invite code\n"
      "  /peers                       list known peers\n"
      "  /chat <peer>                 request an encrypted chat\n"
      "  /requests                    list incoming chat requests\n"
      "  /accept <peer>               accept a chat request\n"
      "  /decline <peer>              decline a chat request\n"
      "  /sessions                    list conversations\n"
      "  /open <index|sid|name>       select a conversation\n"
      "  /msg <text> or plain text    send to the selected conversation\n"
      "  /history [n]                 show local message history\n"
      "  /group <label>               create a group and print its invite\n"
      "  /join <group-invite>         join a group with a session key\n"
      "  /ginvite                     print the group invite for the selected group\n"
      "  /mode <auto|direct|onion>    choose routing mode\n"
      "  /stats                       show session and routing counters\n"
      "  /wipe WIPE                   panic-wipe identity and history\n"
      "  /quit                        exit\n"
      "\nMessages are sealed with the session key. With at least 3 online peers, auto\n"
      "mode routes through a random onion path; otherwise it uses a direct UDP tunnel.\n";
}

void ConsoleApp::print_peers() const {
  auto peers = node_.peers();
  if (peers.empty()) {
    std::cout << "\nNo peers yet. Share /invite and /add the code you receive.\n";
    return;
  }
  std::cout << "\n #  NAME                 STATUS   FINGERPRINT        ENDPOINT\n";
  for (std::size_t i = 0; i < peers.size(); ++i) {
    const auto& peer = peers[i];
    const std::string name = display_safe(peer.name);
    std::cout << " " << (i + 1) << "  " << name;
    std::cout << std::string(name.size() < 20 ? 21 - name.size() : 1, ' ');
    std::cout << (peer.online ? "online " : "offline") << "  " << peer.fingerprint << "  "
              << (peer.endpoint.valid() ? peer.endpoint.to_string() : "-") << "\n";
  }
}

void ConsoleApp::print_requests() const {
  auto requests = node_.requests();
  if (requests.empty()) {
    std::cout << "\nNo incoming chat requests.\n";
    return;
  }
  for (const auto& request : requests) {
    const std::string name = display_safe(request.name);
    std::cout << "  " << name << "  " << request.fingerprint
              << "   /accept " << name << "\n";
  }
}

void ConsoleApp::print_sessions() const {
  auto sessions = node_.session_views();
  if (sessions.empty()) {
    std::cout << "\nNo conversations yet. Use /chat <peer>.\n";
    return;
  }
  std::cout << "\n #  LABEL                SID           STATE   TYPE\n";
  for (std::size_t i = 0; i < sessions.size(); ++i) {
    const auto& view = sessions[i];
    const std::string label = display_safe(view.label);
    std::cout << " " << (i + 1) << "  " << label
              << std::string(label.size() < 20 ? 21 - label.size() : 1, ' ')
              << short_sid(view.sid) << "      "
              << (view.active ? "active " : "history") << " " << (view.group ? "group" : "direct")
              << "\n";
  }
}

void ConsoleApp::print_history(std::size_t limit) const {
  if (!active_) {
    std::cout << "\nSelect a conversation with /open first.\n";
    return;
  }
  auto messages = node_.history(*active_, limit);
  if (messages.empty()) {
    std::cout << "\nNo stored messages in this conversation.\n";
    return;
  }
  std::cout << "\n";
  for (const auto& message : messages) {
    const std::string name = display_safe(message.from_name);
    std::cout << (message.outgoing ? "you> " : (name + "> ")) << display_safe(message.text)
              << "\n";
  }
}

void ConsoleApp::print_session_detail(const SessionView& view) const {
  std::cout << "\n" << display_safe(view.label) << "  sid " << short_sid(view.sid)
            << (view.active ? "  active" : "  history only")
            << (view.group ? "  group" : "  direct") << "\n";
  if (!view.group && !is_zero(view.peer_pk)) {
    std::cout << "peer " << pretty_fingerprint(view.peer_pk) << "\n";
  }
  if (view.group) {
    std::cout << "members: " << view.members.size() << " known\n";
  }
}

void ConsoleApp::select_session(const SessionView& view) {
  active_ = view.sid;
  print_session_detail(view);
}

void ConsoleApp::send_active(const std::string& text) {
  if (!active_) {
    std::cout << "\nNo active conversation. Use /chat <peer> or /open <session>.\n";
    return;
  }
  std::string error;
  bool onion = false;
  std::size_t relays = 0;
  if (!node_.send_text(*active_, text, error, &onion, &relays)) {
    std::cout << "\n[not sent] " << error << "\n";
    return;
  }
  std::cout << "\nyou> " << display_safe(text) << "\n";
  if (onion) {
    std::cout << "[sent via " << relays << " relays]\n";
  } else {
    std::cout << "[sent directly over encrypted UDP]\n";
  }
}

void ConsoleApp::handle_command(const std::string& line) {
  const std::string trimmed = trim(line);
  if (trimmed.empty()) return;

  if (trimmed[0] != '/') {
    send_active(trimmed);
    return;
  }

  auto parts = split_command(trimmed);
  const std::string command = parts[0];

  if (command == "/help" || command == "/?") {
    print_help();
  } else if (command == "/quit" || command == "/exit") {
    quit_ = true;
  } else if (command == "/whoami") {
    std::cout << "\n" << node_.username() << "  " << node_.fingerprint() << "\n";
    std::cout << "UDP port " << node_.listen_port() << "  mode " << node_.mode() << "\n";
    std::cout << "Invite:\n" << node_.own_invite() << "\n";
  } else if (command == "/invite") {
    std::cout << "\n" << node_.own_invite() << "\n";
  } else if (command == "/add") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /add <invite-code>\n";
      return;
    }
    std::string error;
    const std::string code = join_from(parts, 1);
    if (node_.add_contact(code, error)) {
      std::cout << "\n[contact added]" << (error.empty() ? "" : " " + error) << "\n";
    } else {
      std::cout << "\n[error] " << error << "\n";
    }
  } else if (command == "/peers") {
    print_peers();
  } else if (command == "/requests") {
    print_requests();
  } else if (command == "/chat") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /chat <peer>\n";
      return;
    }
    std::string message;
    if (node_.request_chat(join_from(parts, 1), message)) {
      std::cout << "\n" << message << "\n";
    } else {
      std::cout << "\n[error] " << message << "\n";
    }
  } else if (command == "/accept") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /accept <peer>\n";
      return;
    }
    std::string message;
    if (node_.accept_chat(join_from(parts, 1), message)) {
      std::cout << "\n" << message << "\n";
    } else {
      std::cout << "\n[error] " << message << "\n";
    }
  } else if (command == "/decline") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /decline <peer>\n";
      return;
    }
    std::string message;
    if (node_.decline_chat(join_from(parts, 1), message)) {
      std::cout << "\n" << message << "\n";
    } else {
      std::cout << "\n[error] " << message << "\n";
    }
  } else if (command == "/sessions") {
    print_sessions();
  } else if (command == "/open") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /open <index|sid|name>\n";
      return;
    }
    auto sid = node_.resolve_session(join_from(parts, 1));
    if (!sid) {
      std::cout << "\n[session not found]\n";
      return;
    }
    for (const auto& view : node_.session_views()) {
      if (view.sid == *sid) {
        select_session(view);
        return;
      }
    }
  } else if (command == "/msg" || command == "/send") {
    send_active(join_from(parts, 1));
  } else if (command == "/history") {
    std::size_t limit = 200;
    if (parts.size() >= 2) {
      try {
        limit = static_cast<std::size_t>(std::stoul(parts[1]));
      } catch (...) {
        limit = 200;
      }
    }
    print_history(std::min<std::size_t>(limit, 2000));
  } else if (command == "/group") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /group <label>\n";
      return;
    }
    std::string error;
    const std::string code = node_.create_group(join_from(parts, 1), error);
    if (code.empty()) {
      std::cout << "\n[error] " << error << "\n";
    } else {
      std::cout << "\nGroup invite (contains the session key; share only with people you trust):\n"
                << code << "\n";
    }
  } else if (command == "/join") {
    if (parts.size() < 2) {
      std::cout << "\nUsage: /join <group-invite>\n";
      return;
    }
    std::string error;
    SessionId sid{};
    if (node_.join_group(join_from(parts, 1), sid, error)) {
      for (const auto& view : node_.session_views()) {
        if (view.sid == sid) select_session(view);
      }
      std::cout << "\n[joined] waiting for a member to publish the join notice\n";
    } else {
      std::cout << "\n[error] " << error << "\n";
    }
  } else if (command == "/ginvite") {
    if (!active_) {
      std::cout << "\nSelect a group with /open first.\n";
      return;
    }
    std::string error;
    const std::string code = node_.group_invite(*active_, error);
    if (code.empty()) {
      std::cout << "\n[error] " << error << "\n";
    } else {
      std::cout << "\n" << code << "\n";
    }
  } else if (command == "/mode") {
    if (parts.size() < 2) {
      std::cout << "\nCurrent mode: " << node_.mode() << "\n";
      return;
    }
    const std::string mode = parts[1];
    if (mode != "auto" && mode != "direct" && mode != "onion") {
      std::cout << "\nMode must be auto, direct or onion.\n";
      return;
    }
    node_.set_mode(mode);
    std::cout << "\nMode set to " << mode << ".\n";
  } else if (command == "/stats") {
    const auto& stats = node_.stats();
    std::cout << "\nDirect sent: " << stats.direct_sent << "  Onion sent: " << stats.onion_sent
              << "  Relayed: " << stats.relayed << "  Delivered: " << stats.delivered
              << "  Dropped: " << stats.dropped << "\n";
    std::cout << "Peers: " << node_.peers().size() << "  Sessions: "
              << node_.session_views().size() << "  Mode: " << node_.mode() << "\n";
  } else if (command == "/wipe") {
    if (parts.size() < 2 || parts[1] != "WIPE") {
      std::cout << "\nThis erases your identity, keys and history. Type /wipe WIPE to confirm.\n";
      return;
    }
    std::string error;
    node_.panic_wipe(error);
    std::cout << "\nAll local identity and chat data erased. Exiting.\n";
    quit_ = true;
  } else {
    std::cout << "\nUnknown command. /help for the list.\n";
  }
}

int ConsoleApp::run() {
  std::string error;
  if (!node_.start(error)) {
    std::cerr << "startup failed: " << error << "\n";
    return 1;
  }

  std::cout << "\nJargonet  " << node_.username() << "  " << node_.fingerprint() << "\n"
            << "UDP port " << node_.listen_port()
            << (node_.mode() == "auto" ? "  routing auto (onion when 3+ peers)" : "  routing " + node_.mode())
            << "\nType /help for commands, /invite to share your invite.\n";
  print_prompt();
  start_input_thread();

  while (!quit_) {
    node_.run_once(50);
    std::deque<std::string> commands;
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      commands.swap(queue_);
    }
    for (const auto& command : commands) {
      if (quit_) break;
      handle_command(command);
      print_prompt();
    }
  }

  node_.stop();
  return 0;
}

}  // namespace jn
