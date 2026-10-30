#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/bytes.hpp"
#include "core/crypto.hpp"
#include "net/endpoint.hpp"
#include "net/udp_socket.hpp"

namespace jn::mesh {

struct PeerInfo {
  PublicKey pk{};
  std::string name;
  std::string host;
  std::uint16_t port = 0;
  std::chrono::steady_clock::time_point last_seen{};

  std::string short_fingerprint() const;
};

struct RelayReport {
  std::string previous;
  std::string next_name;
  Endpoint next_endpoint;
  std::size_t received_bytes = 0;
  Bytes forwarded;
};

struct SendOutcome {
  bool ok = false;
  bool direct = true;
  std::size_t relays = 0;
  std::string target;
  std::string route;
  std::string note;
  std::string error;
};

struct MeshPacket {
  std::uint8_t type = 0;
  std::uint8_t ttl = 1;
  Bytes payload;
};

// One LAN peer. Discovery is limited UDP broadcast plus optional manual seeds;
// direct messages and onion layers are libsodium sealed boxes over UDP.
class MeshNode {
 public:
  static constexpr std::uint16_t kDiscoveryPort = 9999;
  static constexpr std::size_t kMaxPayload = 8183;
  static constexpr std::size_t kMaxText = 700;

  struct Config {
    std::string name;
    std::uint16_t port = 0;
    std::vector<Endpoint> seeds;
  };

  explicit MeshNode(Config config);
  ~MeshNode();

  MeshNode(const MeshNode&) = delete;
  MeshNode& operator=(const MeshNode&) = delete;

  bool start(std::string& error);
  void stop();
  bool running() const { return running_.load(); }

  SendOutcome send_message(const std::string& target, const std::string& text,
                           int requested_relays);

  std::vector<PeerInfo> peers() const;
  std::string name() const { return name_; }
  std::string short_fingerprint() const;
  PublicKey public_key() const { return key_.pk; }
  std::uint16_t unicast_port() const { return unicast_port_; }
  std::uint16_t discovery_port() const { return kDiscoveryPort; }

  std::function<void(const std::vector<PeerInfo>&)> on_peers;
  std::function<void(const PeerInfo&)> on_peer_online;
  std::function<void(const std::string&)> on_peer_offline;
  std::function<void(const std::string& from, const std::string& text, std::uint64_t hops)>
      on_message;
  std::function<void(const RelayReport&)> on_relay;
  std::function<void(std::size_t bytes, const Bytes& payload)> on_packet;
  std::function<void(const std::string&)> on_notice;
  std::function<void(const std::string&)> on_error;

 private:
  void run_loop();
  void handle_datagram(const Datagram& datagram, bool from_discovery);
  void handle_hello(const Bytes& payload, const Endpoint& from, bool from_discovery);
  void handle_bye(const Bytes& payload);
  void handle_direct(const Bytes& payload, const Endpoint& from);
  void handle_onion(const MeshPacket& packet, const Endpoint& from);

  void broadcast_hello();
  void send_hello_to_seeds();
  void send_hello_to(const Endpoint& endpoint, bool via_discovery);
  Bytes make_hello_payload() const;
  Bytes make_bye_payload() const;
  void send_bye();

  void expire_peers();
  void emit_peers();
  void emit_notice(const std::string& text);
  void emit_error(const std::string& text);

  bool send_packet(const MeshPacket& packet, const Endpoint& endpoint, bool via_discovery);
  bool send_bytes(const Bytes& wire, const Endpoint& endpoint, bool via_discovery);

  std::string previous_hop(const Endpoint& from);
  std::optional<PeerInfo> resolve_target(const std::vector<PeerInfo>& all,
                                         const std::string& query,
                                         std::string& error) const;

  Config config_;
  std::string name_;
  KeyPair key_;
  UdpSocket discovery_;
  UdpSocket unicast_;
  std::uint16_t unicast_port_ = 0;

  std::atomic<bool> running_{false};
  std::thread thread_;

  mutable std::mutex peers_mutex_;
  std::unordered_map<std::string, PeerInfo> peers_;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> hello_replies_;
  mutable std::mutex send_mutex_;

  std::chrono::steady_clock::time_point last_broadcast_{};
  std::chrono::steady_clock::time_point last_seed_hello_{};
  std::chrono::steady_clock::time_point last_expire_{};
  bool broadcast_error_reported_ = false;
};

}  // namespace jn::mesh
