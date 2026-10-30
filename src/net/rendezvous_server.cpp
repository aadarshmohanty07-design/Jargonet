#include "net/rendezvous_server.hpp"

#include <algorithm>
#include <cstring>

#include "core/encoding.hpp"
#include "net/rendezvous.hpp"

namespace jn {
namespace {

std::string tag_key(const RendezvousTag& tag) { return hex_encode(tag.data(), tag.size()); }

std::string ip_key(const Endpoint& ep) { return ep.host; }

}  // namespace

RendezvousServer::RendezvousServer() : RendezvousServer(Config{}) {}

RendezvousServer::RendezvousServer(Config config) : config_(std::move(config)) {}

bool RendezvousServer::start(std::string& error) {
  if (!socket_.open(config_.bind.port, error)) return false;
  next_prune_ = std::chrono::steady_clock::now();
  return true;
}

void RendezvousServer::stop() { socket_.close(); }

std::size_t RendezvousServer::registered_endpoint_count() const {
  std::size_t count = 0;
  for (const auto& [key, state] : tags_) {
    (void)key;
    count += state.entries.size();
  }
  return count;
}

bool RendezvousServer::allow_request(const Endpoint& from) {
  const auto now = std::chrono::steady_clock::now();
  auto& state = ip_windows_[ip_key(from)];
  if (state.window_start.time_since_epoch().count() == 0 ||
      now - state.window_start > std::chrono::seconds(10)) {
    state.window_start = now;
    state.requests = 0;
  }
  if (state.requests++ >= 120) return false;
  return true;
}

void RendezvousServer::send(const Endpoint& to, const Bytes& data) {
  socket_.send_to(to, data);
}

void RendezvousServer::handle_register(const msg::Value& request, const Endpoint& from) {
  const std::uint64_t id = request.has("id") ? request.at("id").as_uint() : 0;
  try {
    const Bytes& raw = request.at("tag").as_bin();
    if (raw.size() != kRendezvousTagBytes) {
      send(from, make_error_response(id, "invalid tag"));
      return;
    }
    RendezvousTag tag{};
    std::copy(raw.begin(), raw.end(), tag.begin());

    std::uint32_t ttl = config_.default_ttl_seconds;
    if (request.has("ttl")) {
      ttl = static_cast<std::uint32_t>(std::min<std::uint64_t>(
          request.at("ttl").as_uint(), config_.max_ttl_seconds));
      ttl = std::max<std::uint32_t>(ttl, 30);
    }

    std::string key = tag_key(tag);
    auto& state = tags_[key];
    if (state.entries.empty()) {
      if (tags_.size() > config_.max_tags_total) {
        tags_.erase(key);
        send(from, make_error_response(id, "server full"));
        return;
      }
      auto& count = tags_per_ip_[ip_key(from)];
      if (count >= config_.max_tags_per_ip) {
        tags_.erase(key);
        send(from, make_error_response(id, "tag quota exceeded"));
        return;
      }
      ++count;
    }

    const auto expires = std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
    bool replaced = false;
    for (auto& entry : state.entries) {
      if (entry.endpoint == from) {
        entry.expires = expires;
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      if (state.entries.size() >= config_.max_entries_per_tag) {
        state.entries.erase(state.entries.begin());
      }
      state.entries.push_back(Entry{from, expires});
    }
    send(from, make_ok_response(id));
  } catch (const msg::Error&) {
    send(from, make_error_response(id, "malformed register"));
  }
}

void RendezvousServer::handle_lookup(const msg::Value& request, const Endpoint& from) {
  const std::uint64_t id = request.has("id") ? request.at("id").as_uint() : 0;
  try {
    const Bytes& raw = request.at("tag").as_bin();
    if (raw.size() != kRendezvousTagBytes) {
      send(from, make_error_response(id, "invalid tag"));
      return;
    }
    RendezvousTag tag{};
    std::copy(raw.begin(), raw.end(), tag.begin());

    std::vector<Endpoint> peers;
    auto it = tags_.find(tag_key(tag));
    if (it != tags_.end()) {
      const auto now = std::chrono::steady_clock::now();
      for (const auto& entry : it->second.entries) {
        if (entry.expires > now && entry.endpoint != from) {
          peers.push_back(entry.endpoint);
          if (peers.size() >= config_.max_entries_per_tag) break;
        }
      }
    }
    send(from, make_peers_response(id, peers));
  } catch (const msg::Error&) {
    send(from, make_error_response(id, "malformed lookup"));
  }
}

void RendezvousServer::handle_unregister(const msg::Value& request, const Endpoint& from) {
  const std::uint64_t id = request.has("id") ? request.at("id").as_uint() : 0;
  try {
    const Bytes& raw = request.at("tag").as_bin();
    if (raw.size() != kRendezvousTagBytes) {
      send(from, make_error_response(id, "invalid tag"));
      return;
    }
    RendezvousTag tag{};
    std::copy(raw.begin(), raw.end(), tag.begin());
    auto it = tags_.find(tag_key(tag));
    if (it != tags_.end()) {
      auto& entries = it->second.entries;
      entries.erase(std::remove_if(entries.begin(), entries.end(),
                                   [&](const Entry& e) { return e.endpoint == from; }),
                    entries.end());
      if (entries.empty()) {
        tags_.erase(it);
        auto count = tags_per_ip_.find(ip_key(from));
        if (count != tags_per_ip_.end() && count->second > 0) --count->second;
      }
    }
    send(from, make_ok_response(id));
  } catch (const msg::Error&) {
    send(from, make_error_response(id, "malformed unregister"));
  }
}

void RendezvousServer::prune() {
  const auto now = std::chrono::steady_clock::now();
  for (auto it = tags_.begin(); it != tags_.end();) {
    auto& entries = it->second.entries;
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const Entry& e) { return e.expires <= now; }),
                  entries.end());
    if (entries.empty()) {
      it = tags_.erase(it);
    } else {
      ++it;
    }
  }

  for (auto it = ip_windows_.begin(); it != ip_windows_.end();) {
    if (now - it->second.window_start > std::chrono::minutes(10)) {
      it = ip_windows_.erase(it);
    } else {
      ++it;
    }
  }
  std::erase_if(tags_per_ip_, [](const auto& pair) { return pair.second == 0; });
  next_prune_ = now + std::chrono::seconds(5);
}

void RendezvousServer::run_once(int timeout_ms) {
  const auto now = std::chrono::steady_clock::now();
  if (now >= next_prune_) prune();

  if (!socket_.wait_readable(timeout_ms)) return;
  auto datagram = socket_.recv_from();
  if (!datagram) return;
  if (!allow_request(datagram->from)) return;

  auto message = decode_rendezvous(datagram->data);
  if (!message || message->type != msg::Value::Type::Map) return;
  const msg::Value* type = message->find("t");
  if (!type || type->type != msg::Value::Type::Str) return;

  if (type->str == "reg") {
    handle_register(*message, datagram->from);
  } else if (type->str == "lookup") {
    handle_lookup(*message, datagram->from);
  } else if (type->str == "unreg") {
    handle_unregister(*message, datagram->from);
  }
}

}  // namespace jn
