#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "app/invite.hpp"
#include "core/identity.hpp"
#include "core/packet.hpp"
#include "net/rendezvous.hpp"
#include "net/udp_socket.hpp"
#include "routing/onion.hpp"
#include "session/dispatcher.hpp"
#include "session/session_manager.hpp"
#include "storage/local_store.hpp"

namespace jn {

struct NodeConfig {
  std::filesystem::path data_dir;
  std::uint16_t listen_port = 0;
  std::optional<Endpoint> rendezvous;
  std::optional<Endpoint> stun;
  std::optional<Endpoint> advertise;
  bool relay_enabled = true;
  bool auto_accept = false;
  std::string mode = "auto";  // auto | direct | onion
  int onion_min_hops = 3;
  int onion_max_hops = 5;
};

struct PeerInfo {
  PublicKey pk{};
  SignPublicKey sign_pk{};
  std::string name;
  std::string fingerprint;
  Endpoint endpoint;
  bool online = false;
  bool relay = true;
};

struct PendingRequestInfo {
  PublicKey pk{};
  std::string name;
  std::string fingerprint;
};

struct IncomingMessage {
  SessionId sid{};
  std::string session_label;
  PublicKey from_pk{};
  std::string from_name;
  std::string text;
  bool group = false;
  ChatKind kind = ChatKind::Chat;
  bool onion = false;
};

struct NodeStats {
  std::uint64_t direct_sent = 0;
  std::uint64_t onion_sent = 0;
  std::uint64_t relayed = 0;
  std::uint64_t delivered = 0;
  std::uint64_t dropped = 0;
};

class Node {
 public:
  Node(NodeConfig config, Identity identity, const std::string& password);
  ~Node();

  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  bool start(std::string& error);
  void stop();
  void run_once(int timeout_ms = 50);

  bool add_contact(const std::string& invite_code, std::string& error);
  bool request_chat(const std::string& peer_query, std::string& message);
  bool accept_chat(const std::string& peer_query, std::string& message);
  bool decline_chat(const std::string& peer_query, std::string& message);

  bool send_text(const SessionId& sid, const std::string& text, std::string& error,
                 bool* used_onion = nullptr, std::size_t* relay_count = nullptr);

  std::string create_group(const std::string& label, std::string& error);
  bool join_group(const std::string& invite_code, SessionId& joined, std::string& error);
  std::string group_invite(const SessionId& sid, std::string& error) const;

  std::vector<PeerInfo> peers() const;
  std::vector<PendingRequestInfo> requests() const;
  std::vector<SessionView> session_views() const;
  std::vector<StoredMessage> history(const SessionId& sid, std::size_t limit = 200) const;

  std::optional<PublicKey> resolve_peer(const std::string& query) const;
  std::optional<SessionId> resolve_session(const std::string& query) const;

  std::string own_invite() const;
  std::string username() const { return identity_.username; }
  std::string fingerprint() const { return identity_.fingerprint(); }
  std::uint16_t listen_port() const { return socket_.local_port(); }
  const Identity& identity() const { return identity_; }
  const NodeStats& stats() const { return stats_; }
  std::string mode() const { return config_.mode; }
  void set_mode(const std::string& mode);

  bool panic_wipe(std::string& error);

  std::function<void(const IncomingMessage&)> on_message;
  std::function<void(const PendingRequestInfo&)> on_request;
  std::function<void(const SessionView&)> on_session;
  std::function<void(const std::string&)> on_system;

 private:
  struct Peer {
    PublicKey pk{};
    SignPublicKey sign_pk{};
    std::string name;
    std::vector<Endpoint> endpoints;
    Endpoint last_endpoint;
    std::chrono::steady_clock::time_point last_seen{};
    std::chrono::steady_clock::time_point last_hello_sent{};
    std::chrono::steady_clock::time_point last_lookup{};
    bool relay = true;
    bool online = false;
  };

  struct OutgoingRequest {
    PublicKey peer{};
    std::string name;
    KeyPair ephemeral;
    Endpoint endpoint;
    std::uint64_t msg_id = 0;
    Bytes wire;
    int attempts = 0;
    std::chrono::steady_clock::time_point next_retry{};
    std::chrono::steady_clock::time_point expires{};
  };

  struct IncomingRequest {
    PublicKey peer{};
    SignPublicKey sign_pk{};
    std::string name;
    PublicKey ephemeral_pk{};
    Endpoint endpoint;
    std::chrono::steady_clock::time_point received{};
  };

  struct PendingWire {
    Bytes wire;
    Endpoint dest;
    int attempts = 0;
    std::chrono::steady_clock::time_point next_retry{};
  };

  void handle_datagram(const Datagram& datagram);
  void handle_packet(const Packet& packet, const Endpoint& from);
  void handle_hello(const Packet& packet, const Endpoint& from);
  void handle_chat_request(const Packet& packet, const Endpoint& from);
  void handle_chat_accept(const Packet& packet, const Endpoint& from);
  void handle_direct(const Packet& packet, const Endpoint& from);
  void handle_onion(const Packet& packet, const Endpoint& from);
  void handle_ratchet(const Packet& packet, const Endpoint& from);
  void handle_ack(const Packet& packet, const Endpoint& from);
  void handle_rendezvous(const Datagram& datagram);

  void process_timers();
  void retry_pending();
  void send_keepalives();
  void rendezvous_tick();
  void maybe_ratchet();
  void maybe_send_group_join();
  void expire_seen();

  void send_packet(const Packet& packet, const Endpoint& endpoint);
  void send_wire(const Bytes& wire, const Endpoint& endpoint);
  void send_ack(const Endpoint& endpoint, std::uint64_t msg_id);
  bool track_reliable(const Packet& packet, const Endpoint& endpoint);
  void send_hello(Peer& peer);
  void send_hello_to_endpoints(Peer& peer);
  void discover_via_rendezvous(const Peer& peer);
  void register_rendezvous();

  Bytes make_sender_box(const PublicKey& recipient, const Bytes& plaintext) const;
  std::optional<Bytes> open_sender_box(const Bytes& payload, PublicKey& sender,
                                       std::string& error) const;

  Peer& peer_for(const PublicKey& pk, const std::string& name = {});
  const Peer* find_peer(const PublicKey& pk) const;
  Endpoint endpoint_of(const Peer& peer) const;
  std::optional<PublicKey> peer_by_endpoint(const Endpoint& endpoint) const;
  void add_endpoint(Peer& peer, const Endpoint& endpoint);
  void mark_seen(Peer& peer, const Endpoint& endpoint);
  void persist_contact(const Peer& peer);
  std::vector<OnionHop> relay_candidates(const PublicKey& recipient) const;
  bool send_group_message(Session& session, const std::string& text, ChatKind kind,
                          std::uint64_t msg_id, std::uint64_t seq, std::string& error,
                          bool join_notice);
  void notify_session(Session& session);
  void emit_system(const std::string& message);
  bool accept_incoming(const PublicKey& pk, std::string& message);
  bool send_join_notice(Session& session);

  bool seen_message(const SessionId& sid, std::uint64_t msg_id);
  bool seen_onion(const Bytes& payload);
  bool within_rate(const PublicKey& pk, std::chrono::steady_clock::time_point now,
                   std::chrono::seconds window, std::unordered_map<std::string,
                   std::chrono::steady_clock::time_point>& table);

  NodeConfig config_;
  Identity identity_;
  std::unique_ptr<LocalStore> store_;
  std::unique_ptr<SessionManager> sessions_;
  MessageDispatcher dispatcher_;
  UdpSocket socket_;
  bool started_ = false;

  std::unordered_map<std::string, Peer> peers_;
  std::unordered_map<std::string, OutgoingRequest> outgoing_requests_;
  std::unordered_map<std::string, IncomingRequest> incoming_requests_;
  std::unordered_map<std::uint64_t, PendingWire> pending_wire_;
  std::unordered_map<std::uint64_t, PublicKey> rv_lookups_;
  std::unordered_set<std::string> notified_joins_;

  std::vector<Endpoint> my_endpoints_;
  Endpoint rv_endpoint_;
  std::string rv_string_;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> join_attempts_;
  std::chrono::steady_clock::time_point last_rv_register_{};
  std::chrono::steady_clock::time_point last_keepalive_{};
  std::chrono::steady_clock::time_point last_ratchet_check_{};

  struct SeenEntry {
    std::string key;
    std::chrono::steady_clock::time_point when;
  };
  std::unordered_set<std::string> seen_messages_;
  std::deque<SeenEntry> seen_message_order_;
  std::unordered_set<std::string> seen_onions_;
  std::deque<SeenEntry> seen_onion_order_;

  NodeStats stats_;
  std::uint64_t next_rendezvous_id_ = 1;
};

}  // namespace jn
