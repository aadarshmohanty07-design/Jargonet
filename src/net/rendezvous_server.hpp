#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "net/endpoint.hpp"
#include "core/msgpack.hpp"
#include "net/udp_socket.hpp"

namespace jn {

// Zero-knowledge rendezvous service. It learns opaque tags and observed UDP
// endpoints only. It does not log IP addresses, usernames, keys or content.
class RendezvousServer {
 public:
  struct Config {
    Endpoint bind{"0.0.0.0", 47400};
    std::uint32_t default_ttl_seconds = 120;
    std::uint32_t max_ttl_seconds = 600;
    std::size_t max_entries_per_tag = 8;
    std::size_t max_tags_per_ip = 64;
    std::size_t max_tags_total = 100000;
  };

  RendezvousServer();
  explicit RendezvousServer(Config config);

  bool start(std::string& error);
  void stop();
  void run_once(int timeout_ms = 200);
  void prune();

  std::uint16_t port() const { return socket_.local_port(); }
  std::size_t tag_count() const { return tags_.size(); }
  std::size_t registered_endpoint_count() const;

 private:
  struct Entry {
    Endpoint endpoint;
    std::chrono::steady_clock::time_point expires;
  };
  struct TagState {
    std::vector<Entry> entries;
    std::size_t owner_slots = 0;
  };
  struct IpState {
    std::chrono::steady_clock::time_point window_start;
    std::uint32_t requests = 0;
  };

  void handle_register(const msg::Value& request, const Endpoint& from);
  void handle_lookup(const msg::Value& request, const Endpoint& from);
  void handle_unregister(const msg::Value& request, const Endpoint& from);
  bool allow_request(const Endpoint& from);
  void send(const Endpoint& to, const Bytes& data);

  Config config_;
  UdpSocket socket_;
  std::unordered_map<std::string, TagState> tags_;
  std::unordered_map<std::string, IpState> ip_windows_;
  std::unordered_map<std::string, std::size_t> tags_per_ip_;
  std::chrono::steady_clock::time_point next_prune_;
};

}  // namespace jn
