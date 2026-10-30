#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "app/node.hpp"
#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/identity.hpp"
#include "storage/local_store.hpp"
#include "test_util.hpp"

using namespace jn;
using Clock = std::chrono::steady_clock;

namespace {

const std::string kPassword = "correct horse battery staple";

void pump(const std::vector<std::unique_ptr<Node>>& nodes, int milliseconds) {
  const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
  do {
    for (const auto& node : nodes) node->run_once(2);
  } while (Clock::now() < deadline);
}

template <typename Predicate>
bool wait_for(const std::vector<std::unique_ptr<Node>>& nodes, Predicate predicate,
              int timeout_ms = 4000) {
  const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
  while (Clock::now() < deadline) {
    if (predicate()) return true;
    for (const auto& node : nodes) node->run_once(2);
  }
  return predicate();
}

std::optional<SessionView> active_session_labeled(Node& node, const std::string& label) {
  for (const auto& view : node.session_views()) {
    if (view.active && iequals(view.label, label)) return view;
  }
  return std::nullopt;
}

bool has_message(const std::vector<IncomingMessage>& messages, const std::string& text) {
  for (const auto& message : messages) {
    if (message.text == text) return true;
  }
  return false;
}

}  // namespace

void run() {
  std::vector<std::filesystem::path> dirs;
  std::vector<std::unique_ptr<Node>> nodes;
  const char* names[] = {"alice", "bob", "carol", "dave", "erin"};

  for (int i = 0; i < 5; ++i) {
    auto dir = jntest::temp_dir(std::string("node-") + names[i]);
    dirs.push_back(dir);
    Identity identity = IdentityManager::create(dir, names[i], kPassword);
    NodeConfig config;
    config.data_dir = dir;
    config.listen_port = 0;
    config.mode = "direct";
    config.advertise = Endpoint{"127.0.0.1", 0};
    config.relay_enabled = true;
    nodes.push_back(std::make_unique<Node>(config, std::move(identity), kPassword));
    std::string error;
    CHECK(nodes.back()->start(error));
    if (!error.empty()) std::cerr << "start: " << error << "\n";
  }
  CHECK(nodes.size() == 5);

  std::vector<IncomingMessage> messages_0, messages_1, messages_2, messages_3, messages_4;
  nodes[0]->on_message = [&](const IncomingMessage& m) { messages_0.push_back(m); };
  nodes[1]->on_message = [&](const IncomingMessage& m) { messages_1.push_back(m); };
  nodes[2]->on_message = [&](const IncomingMessage& m) { messages_2.push_back(m); };
  nodes[3]->on_message = [&](const IncomingMessage& m) { messages_3.push_back(m); };
  nodes[4]->on_message = [&](const IncomingMessage& m) { messages_4.push_back(m); };

  // Everyone knows everyone; invites carry loopback endpoints.
  for (int i = 0; i < 5; ++i) {
    for (int j = 0; j < 5; ++j) {
      if (i == j) continue;
      std::string error;
      CHECK(nodes[i]->add_contact(nodes[j]->own_invite(), error));
    }
  }

  CHECK(wait_for(nodes, [&] {
    for (const auto& node : nodes) {
      int online = 0;
      for (const auto& peer : node->peers()) {
        if (peer.online) ++online;
      }
      if (online != 4) return false;
    }
    return true;
  }));

  for (const auto& node : nodes) {
    CHECK(node->peers().size() == 4);
  }

  // ---------------------------------------------------------------- direct chat
  std::string message;
  CHECK(nodes[0]->request_chat(nodes[1]->fingerprint(), message));
  CHECK(wait_for(nodes, [&] { return nodes[1]->requests().size() == 1; }));
  CHECK(nodes[1]->accept_chat(nodes[0]->fingerprint(), message));
  CHECK(wait_for(nodes, [&] {
    return active_session_labeled(*nodes[0], "bob").has_value() &&
           active_session_labeled(*nodes[1], "alice").has_value();
  }));

  auto direct_sid = nodes[0]->resolve_session("bob");
  CHECK(direct_sid.has_value());
  nodes[0]->set_mode("direct");
  nodes[1]->set_mode("direct");
  std::string error;
  CHECK(nodes[0]->send_text(*direct_sid, "direct hello", error));
  CHECK(wait_for(nodes, [&] { return has_message(messages_1, "direct hello"); }));
  CHECK(!messages_1.empty());
  if (!messages_1.empty()) {
    CHECK(messages_1.back().text == "direct hello");
    CHECK(!messages_1.back().onion);
  }

  auto reply_sid = nodes[1]->resolve_session("alice");
  CHECK(reply_sid.has_value());
  CHECK(nodes[1]->send_text(*reply_sid, "direct reply", error));
  CHECK(wait_for(nodes, [&] { return has_message(messages_0, "direct reply"); }));

  // ---------------------------------------------------------------- onion delivery
  messages_4.clear();
  CHECK(nodes[0]->request_chat(nodes[4]->fingerprint(), message));
  CHECK(wait_for(nodes, [&] { return nodes[4]->requests().size() == 1; }));
  CHECK(nodes[4]->accept_chat(nodes[0]->fingerprint(), message));
  CHECK(wait_for(nodes, [&] {
    return active_session_labeled(*nodes[0], "erin").has_value() &&
           active_session_labeled(*nodes[4], "alice").has_value();
  }));
  auto onion_sid = nodes[0]->resolve_session("erin");
  CHECK(onion_sid.has_value());

  for (const auto& node : nodes) node->set_mode("auto");
  const std::uint64_t relayed_before =
      nodes[1]->stats().relayed + nodes[2]->stats().relayed + nodes[3]->stats().relayed;
  const std::uint64_t delivered_before =
      nodes[1]->stats().delivered + nodes[2]->stats().delivered + nodes[3]->stats().delivered;

  bool used_onion = false;
  std::size_t relay_count = 0;
  CHECK(nodes[0]->send_text(*onion_sid, "onion hello", error, &used_onion, &relay_count));
  CHECK(used_onion);
  CHECK(relay_count == 3);
  CHECK(nodes[0]->stats().onion_sent >= 1);
  CHECK(wait_for(nodes, [&] { return has_message(messages_4, "onion hello"); }, 6000));

  CHECK(!messages_4.empty());
  if (!messages_4.empty()) {
    CHECK(messages_4.back().text == "onion hello");
    CHECK(messages_4.back().onion);
    CHECK(messages_4.back().from_pk == nodes[0]->identity().pk);
  }

  const std::uint64_t relayed_after =
      nodes[1]->stats().relayed + nodes[2]->stats().relayed + nodes[3]->stats().relayed;
  const std::uint64_t delivered_after =
      nodes[1]->stats().delivered + nodes[2]->stats().delivered + nodes[3]->stats().delivered;
  CHECK(relayed_after - relayed_before + delivered_after - delivered_before == relay_count);
  CHECK(relayed_after - relayed_before == relay_count - 1);
  CHECK(delivered_after - delivered_before == 1);

  // Relays only forward opaque layers; they never receive chat content.
  CHECK(messages_1.empty() || !has_message(messages_1, "onion hello"));
  CHECK(messages_2.empty() || !has_message(messages_2, "onion hello"));
  CHECK(messages_3.empty() || !has_message(messages_3, "onion hello"));

  // The recipient can reply directly to a session that arrived over onion.
  nodes[4]->set_mode("direct");
  auto erin_reply_sid = nodes[4]->resolve_session("alice");
  CHECK(erin_reply_sid.has_value());
  if (erin_reply_sid) {
    CHECK(nodes[4]->send_text(*erin_reply_sid, "onion reply", error));
    CHECK(wait_for(nodes, [&] { return has_message(messages_0, "onion reply"); }));
  }

  // ---------------------------------------------------------------- group chat
  nodes[0]->set_mode("direct");
  nodes[1]->set_mode("auto");
  std::string group_invite = nodes[0]->create_group("team", error);
  CHECK(!group_invite.empty());
  auto group_sid_a = nodes[0]->resolve_session("team");
  CHECK(group_sid_a.has_value());

  messages_1.clear();
  SessionId group_sid_b{};
  CHECK(nodes[1]->join_group(group_invite, group_sid_b, error));
  CHECK(group_sid_b == *group_sid_a);
  CHECK(wait_for(nodes, [&] {
    auto view = active_session_labeled(*nodes[0], "team");
    return view.has_value() && !view->members.empty();
  }));
  CHECK(nodes[0]->send_text(*group_sid_a, "group hello", error));
  CHECK(wait_for(nodes, [&] { return has_message(messages_1, "group hello"); }));
  bool group_seen = false;
  for (const auto& incoming : messages_1) {
    if (incoming.text == "group hello") {
      group_seen = true;
      CHECK(incoming.group);
      CHECK(incoming.session_label == "team");
    }
  }
  CHECK(group_seen);

  // A group JOIN that arrives through an onion must not rewrite the joiner's
  // endpoint to the delivery relay. Exercise that path, then send over onion.
  messages_1.clear();
  nodes[0]->set_mode("auto");
  CHECK(nodes[0]->send_text(*group_sid_a, "group onion", error));
  CHECK(wait_for(nodes, [&] { return has_message(messages_1, "group onion"); }));
  bool group_onion_seen = false;
  for (const auto& incoming : messages_1) {
    if (incoming.text == "group onion") {
      group_onion_seen = true;
      CHECK(incoming.group);
      CHECK(incoming.onion);
    }
  }
  CHECK(group_onion_seen);

  // ---------------------------------------------------------------- panic wipe
  CHECK(nodes[4]->panic_wipe(error));
  CHECK(!IdentityManager::exists(dirs[4]));
  CHECK(!read_file(dirs[4] / LocalStore::kStoreFileName, 32 << 20).has_value());

  nodes.clear();
  for (const auto& dir : dirs) {
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
  }
}

TEST_MAIN()
