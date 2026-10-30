#include "mesh_node.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <utility>

#include "core/encoding.hpp"
#include "core/msgpack.hpp"

namespace jn::mesh {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::uint8_t kVersion = 1;
constexpr std::uint8_t kHello = 1;
constexpr std::uint8_t kDirect = 2;
constexpr std::uint8_t kOnion = 3;
constexpr std::uint8_t kBye = 4;
constexpr std::uint32_t kInnerOnion = 1;
constexpr std::uint32_t kInnerDirect = 2;
constexpr std::size_t kPacketHeader = 9;
constexpr std::size_t kMaxDatagram = MeshNode::kMaxPayload + kPacketHeader;
constexpr std::size_t kMaxRelays = 4;
constexpr auto kPeerTimeout = std::chrono::seconds(10);
constexpr auto kHelloInterval = std::chrono::seconds(2);

bool valid_name(const std::string& name) {
  if (name.empty() || name.size() > 24) return false;
  for (unsigned char c : name) {
    if (!std::isalnum(c) && c != '_' && c != '-') return false;
  }
  return true;
}

std::string safe_text(const std::string& value) {
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

std::string lower_ascii(std::string value) {
  for (char& c : value) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

std::string normalize_fingerprint(const std::string& query) {
  std::string out;
  out.reserve(query.size());
  for (unsigned char c : query) {
    if (c == '-' || c == ' ' || c == '\t') continue;
    out.push_back(static_cast<char>(std::toupper(c)));
  }
  return out;
}

void put_u16(Bytes& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t read_u16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

Bytes encode_packet(std::uint8_t type, std::uint8_t ttl, const Bytes& payload) {
  if (payload.size() > MeshNode::kMaxPayload) return {};
  Bytes out;
  out.reserve(kPacketHeader + payload.size());
  out.push_back('M');
  out.push_back('C');
  out.push_back('H');
  out.push_back('1');
  out.push_back(kVersion);
  out.push_back(type);
  out.push_back(ttl);
  put_u16(out, static_cast<std::uint16_t>(payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::optional<MeshPacket> decode_packet(const std::uint8_t* data, std::size_t size) {
  if (!data || size < kPacketHeader || size > kMaxDatagram) return std::nullopt;
  if (std::memcmp(data, "MCH1", 4) != 0 || data[4] != kVersion) return std::nullopt;
  const std::uint8_t type = data[5];
  const std::uint8_t ttl = data[6];
  if (type < kHello || type > kBye || ttl == 0 || ttl > 8) return std::nullopt;
  const std::size_t length = read_u16(data + 7);
  if (length + kPacketHeader != size) return std::nullopt;
  MeshPacket packet;
  packet.type = type;
  packet.ttl = ttl;
  packet.payload.assign(data + kPacketHeader, data + size);
  return packet;
}

Bytes make_layer(const std::string& next_name, const std::string& next_host,
                 std::uint16_t next_port, std::uint32_t inner_type, const Bytes& inner) {
  msg::Writer writer;
  writer.map(6);
  writer.str("v");
  writer.uint(1);
  writer.str("nn");
  writer.str(next_name);
  writer.str("nh");
  writer.str(next_host);
  writer.str("np");
  writer.uint(next_port);
  writer.str("it");
  writer.uint(inner_type);
  writer.str("d");
  writer.bin(inner);
  return writer.take();
}

}  // namespace

std::string PeerInfo::short_fingerprint() const {
  const std::string full = jn::fingerprint(pk);
  return full.substr(0, 8);
}

MeshNode::MeshNode(Config config)
    : config_(std::move(config)),
      name_(config_.name),
      key_(CryptoEngine::generate_box_keypair()) {}

MeshNode::~MeshNode() { stop(); }

std::string MeshNode::short_fingerprint() const {
  return jn::fingerprint(key_.pk).substr(0, 8);
}

bool MeshNode::start(std::string& error) {
  CryptoEngine::init();
  if (!valid_name(name_)) {
    error = "name must be 1-24 characters: letters, digits, '_' or '-'";
    return false;
  }
  if (config_.port == kDiscoveryPort) {
    error = "--port cannot be 9999; that is the discovery port";
    return false;
  }

  UdpSocketOptions discovery_options;
  discovery_options.reuse_address = true;
  discovery_options.reuse_port = true;
  discovery_options.broadcast = true;
  std::string discovery_error;
  if (!discovery_.open(kDiscoveryPort, discovery_error, discovery_options)) {
    if (config_.seeds.empty()) {
      error = "cannot bind UDP discovery :" + std::to_string(kDiscoveryPort) + " (" +
              discovery_error +
              "). Close the other process or pass --peers <ip:port,...> as a fallback.";
      return false;
    }
    emit_notice("broadcast discovery unavailable (" + discovery_error +
                "); using manual peers");
  }

  std::string unicast_error;
  if (!unicast_.open(config_.port, unicast_error)) {
    discovery_.close();
    error = "cannot bind unicast UDP port: " + unicast_error;
    return false;
  }
  unicast_port_ = unicast_.local_port();
  if (unicast_port_ == 0 || unicast_port_ == kDiscoveryPort) {
    discovery_.close();
    unicast_.close();
    error = "could not obtain a usable unicast UDP port";
    return false;
  }

  broadcast_hello();
  send_hello_to_seeds();
  const auto now = Clock::now();
  last_broadcast_ = now;
  last_seed_hello_ = now;
  last_expire_ = now;

  running_ = true;
  thread_ = std::thread([this] { run_loop(); });
  return true;
}

void MeshNode::stop() {
  const bool was_running = running_.exchange(false);
  if (was_running) send_bye();
  if (thread_.joinable()) thread_.join();
  discovery_.close();
  unicast_.close();
}

void MeshNode::run_loop() {
  auto drain = [&](UdpSocket& socket, bool from_discovery) {
    for (int i = 0; i < 128; ++i) {
      auto datagram = socket.recv_from();
      if (!datagram) break;
      handle_datagram(*datagram, from_discovery);
    }
  };

  while (running_) {
    if (discovery_.is_open()) {
      if (discovery_.wait_readable(10)) drain(discovery_, true);
    } else {
      unicast_.wait_readable(10);
    }
    drain(unicast_, false);

    const auto now = Clock::now();
    if (now - last_broadcast_ >= kHelloInterval) {
      broadcast_hello();
      last_broadcast_ = now;
    }
    if (!config_.seeds.empty() && now - last_seed_hello_ >= kHelloInterval) {
      send_hello_to_seeds();
      last_seed_hello_ = now;
    }
    if (now - last_expire_ >= std::chrono::seconds(1)) {
      expire_peers();
      last_expire_ = now;
    }
  }
}

Bytes MeshNode::make_hello_payload() const {
  msg::Writer writer;
  writer.map(4);
  writer.str("v");
  writer.uint(1);
  writer.str("n");
  writer.str(name_);
  writer.str("k");
  writer.bin(key_.pk.data(), key_.pk.size());
  writer.str("p");
  writer.uint(unicast_port_);
  return writer.take();
}

Bytes MeshNode::make_bye_payload() const {
  msg::Writer writer;
  writer.map(2);
  writer.str("v");
  writer.uint(1);
  writer.str("k");
  writer.bin(key_.pk.data(), key_.pk.size());
  return writer.take();
}

void MeshNode::broadcast_hello() {
  if (!discovery_.is_open()) return;
  MeshPacket hello;
  hello.type = kHello;
  hello.ttl = 1;
  hello.payload = make_hello_payload();
  bool sent = send_packet(hello, Endpoint{"255.255.255.255", kDiscoveryPort}, true);
  // Also try the loopback broadcast. This helps several instances on one
  // laptop when the stack does not loop the limited broadcast back locally.
  sent = send_packet(hello, Endpoint{"127.255.255.255", kDiscoveryPort}, true) || sent;
  if (!sent && !broadcast_error_reported_) {
    broadcast_error_reported_ = true;
    emit_error("broadcast HELLO failed; use --peers <ip:port,...> as a fallback");
  }
}

void MeshNode::send_hello_to_seeds() {
  if (config_.seeds.empty() || !unicast_.is_open()) return;
  MeshPacket hello;
  hello.type = kHello;
  hello.ttl = 1;
  hello.payload = make_hello_payload();
  for (const auto& seed : config_.seeds) {
    send_packet(hello, seed, false);
  }
}

void MeshNode::send_hello_to(const Endpoint& endpoint, bool via_discovery) {
  MeshPacket hello;
  hello.type = kHello;
  hello.ttl = 1;
  hello.payload = make_hello_payload();
  send_packet(hello, endpoint, via_discovery);
}

void MeshNode::send_bye() {
  if (!unicast_.is_open()) return;
  MeshPacket bye;
  bye.type = kBye;
  bye.ttl = 1;
  bye.payload = make_bye_payload();

  std::vector<Endpoint> endpoints;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& [key, peer] : peers_) {
      (void)key;
      endpoints.push_back(Endpoint{peer.host, peer.port});
    }
  }
  if (discovery_.is_open()) {
    send_packet(bye, Endpoint{"255.255.255.255", kDiscoveryPort}, true);
  }
  for (const auto& endpoint : endpoints) {
    send_packet(bye, endpoint, false);
  }
}

bool MeshNode::send_packet(const MeshPacket& packet, const Endpoint& endpoint,
                           bool via_discovery) {
  Bytes wire = encode_packet(packet.type, packet.ttl, packet.payload);
  if (wire.empty()) return false;
  return send_bytes(wire, endpoint, via_discovery);
}

bool MeshNode::send_bytes(const Bytes& wire, const Endpoint& endpoint, bool via_discovery) {
  UdpSocket& socket = via_discovery ? discovery_ : unicast_;
  if (!socket.is_open() || !endpoint.valid()) return false;
  std::lock_guard<std::mutex> lock(send_mutex_);
  return socket.send_to(endpoint, wire);
}

void MeshNode::handle_datagram(const Datagram& datagram, bool from_discovery) {
  auto packet = decode_packet(datagram.data.data(), datagram.data.size());
  if (!packet) return;

  switch (packet->type) {
    case kHello:
      handle_hello(packet->payload, datagram.from, from_discovery);
      break;
    case kBye:
      handle_bye(packet->payload);
      break;
    case kDirect:
      if (on_packet) on_packet(packet->payload.size(), packet->payload);
      handle_direct(packet->payload, datagram.from);
      break;
    case kOnion:
      if (on_packet) on_packet(packet->payload.size(), packet->payload);
      handle_onion(*packet, datagram.from);
      break;
    default:
      break;
  }
}

void MeshNode::handle_hello(const Bytes& payload, const Endpoint& from,
                            bool from_discovery) {
  try {
    msg::Value root = msg::decode(payload);
    if (root.at("v").as_uint() != 1) return;
    const std::string name = root.at("n").as_str();
    if (!valid_name(name)) return;
    const Bytes& pk_bytes = root.at("k").as_bin();
    if (pk_bytes.size() != kPublicKeyBytes) return;
    PublicKey pk{};
    std::copy(pk_bytes.begin(), pk_bytes.end(), pk.begin());
    if (pk == key_.pk || !CryptoEngine::valid_public_key(pk)) return;
    const std::uint64_t port_value = root.at("p").as_uint();
    if (port_value == 0 || port_value > 65535 || port_value == kDiscoveryPort) return;
    if (from.host.empty() || from.host.size() > 64) return;

    const std::uint16_t port = static_cast<std::uint16_t>(port_value);
    const std::string key = hex_encode(pk.data(), pk.size());
    const auto now = Clock::now();
    PeerInfo peer;
    bool is_new = false;
    bool changed = false;
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      auto [it, inserted] = peers_.try_emplace(key);
      if (inserted) {
        it->second.pk = pk;
        it->second.name = name;
        it->second.host = from.host;
        it->second.port = port;
        is_new = true;
        changed = true;
      } else if (it->second.name != name || it->second.host != from.host ||
                 it->second.port != port) {
        it->second.name = name;
        it->second.host = from.host;
        it->second.port = port;
        changed = true;
      }
      it->second.last_seen = now;
      peer = it->second;
    }

    if (is_new && on_peer_online) on_peer_online(peer);
    if (changed) emit_peers();

    // A unicast HELLO can come from a --peers seed. Reply once in a while so the
    // seed learns our name, key and unicast port even when broadcast is blocked.
    if (!from_discovery) {
      auto last = hello_replies_.find(key);
      if (last == hello_replies_.end() ||
          now - last->second >= std::chrono::seconds(2)) {
        hello_replies_[key] = now;
        send_hello_to(Endpoint{from.host, port}, false);
      }
    }
  } catch (const msg::Error&) {
    // Ignore malformed discovery frames.
  }
}

void MeshNode::handle_bye(const Bytes& payload) {
  try {
    msg::Value root = msg::decode(payload);
    if (root.at("v").as_uint() != 1) return;
    const Bytes& pk_bytes = root.at("k").as_bin();
    if (pk_bytes.size() != kPublicKeyBytes) return;
    PublicKey pk{};
    std::copy(pk_bytes.begin(), pk_bytes.end(), pk.begin());
    const std::string key = hex_encode(pk.data(), pk.size());

    std::string label;
    bool removed = false;
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      auto it = peers_.find(key);
      if (it != peers_.end()) {
        label = it->second.name + " (" + it->second.short_fingerprint() + ")";
        peers_.erase(it);
        removed = true;
      }
    }
    if (removed) {
      if (on_peer_offline) on_peer_offline(label);
      emit_peers();
    }
  } catch (const msg::Error&) {
  }
}

void MeshNode::handle_direct(const Bytes& payload, const Endpoint& from) {
  (void)from;
  Bytes plain;
  try {
    plain = CryptoEngine::box_seal_open(key_.pk, key_.sk, payload.data(), payload.size());
  } catch (const CryptoError&) {
    emit_error("direct message could not be opened (wrong key or corrupted packet)");
    return;
  }

  try {
    msg::Value root = msg::decode(plain);
    if (root.at("v").as_uint() != 1) return;
    if (root.at("k").as_bin().size() != kPublicKeyBytes) return;
    std::string name = safe_text(root.at("n").as_str());
    if (name.size() > 64) name.resize(64);
    std::string text = safe_text(root.at("t").as_str());
    if (text.size() > 2048) text.resize(2048);
    const std::uint64_t hops = root.at("h").as_uint();
    if (on_message) on_message(name, text, hops);
  } catch (const msg::Error&) {
    emit_error("direct message has a malformed payload");
  }
}

void MeshNode::handle_onion(const MeshPacket& packet, const Endpoint& from) {
  if (packet.ttl <= 1) {
    emit_error("relay: onion hop limit exhausted");
    return;
  }

  Bytes plain;
  try {
    plain = CryptoEngine::box_seal_open(key_.pk, key_.sk, packet.payload.data(),
                                        packet.payload.size());
  } catch (const CryptoError&) {
    emit_error("relay: cannot open onion layer from " + from.to_string());
    return;
  }

  try {
    msg::Value root = msg::decode(plain);
    if (root.at("v").as_uint() != 1) return;
    const std::string next_name_raw = root.at("nn").as_str();
    const std::string next_host = root.at("nh").as_str();
    const std::uint64_t next_port_value = root.at("np").as_uint();
    const std::uint64_t inner_type = root.at("it").as_uint();
    const Bytes& inner = root.at("d").as_bin();

    for (unsigned char c : next_host) {
      if (c < 0x21 || c > 0x7e) {
        emit_error("relay: invalid next-hop host");
        return;
      }
    }
    if (next_host.empty() || next_host.size() > 64 ||
        next_host.find_first_of(" \t\r\n") != std::string::npos) {
      emit_error("relay: invalid next-hop host");
      return;
    }
    if (next_port_value == 0 || next_port_value > 65535) {
      emit_error("relay: invalid next-hop port");
      return;
    }
    if (inner_type != kInnerOnion && inner_type != kInnerDirect) {
      emit_error("relay: invalid inner packet type");
      return;
    }
    if (inner.empty() || inner.size() > kMaxPayload) {
      emit_error("relay: invalid inner payload");
      return;
    }

    std::string next_name = safe_text(next_name_raw);
    if (next_name.size() > 24) next_name.resize(24);
    if (next_name.empty()) next_name = "next";
    const Endpoint next_endpoint{next_host, static_cast<std::uint16_t>(next_port_value)};

    RelayReport report;
    report.previous = previous_hop(from);
    report.next_name = next_name;
    report.next_endpoint = next_endpoint;
    report.received_bytes = packet.payload.size();
    report.forwarded = inner;
    if (on_relay) on_relay(report);

    MeshPacket forward;
    forward.type = inner_type == kInnerOnion ? kOnion : kDirect;
    forward.ttl = static_cast<std::uint8_t>(packet.ttl - 1);
    forward.payload = inner;
    if (!send_packet(forward, next_endpoint, false)) {
      emit_error("relay: forward to " + next_endpoint.to_string() + " failed");
    }
  } catch (const msg::Error&) {
    emit_error("relay: malformed onion layer");
  }
}

std::string MeshNode::previous_hop(const Endpoint& from) {
  const auto now = Clock::now();
  std::lock_guard<std::mutex> lock(peers_mutex_);
  for (auto& [key, peer] : peers_) {
    (void)key;
    if (peer.host == from.host && peer.port == from.port) {
      peer.last_seen = now;
      return peer.name;
    }
  }
  return from.to_string();
}

void MeshNode::expire_peers() {
  const auto now = Clock::now();
  std::vector<std::string> labels;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto it = peers_.begin(); it != peers_.end();) {
      if (now - it->second.last_seen > kPeerTimeout) {
        labels.push_back(it->second.name + " (" + it->second.short_fingerprint() + ")");
        it = peers_.erase(it);
      } else {
        ++it;
      }
    }
  }
  if (labels.empty()) return;
  for (const auto& label : labels) {
    if (on_peer_offline) on_peer_offline(label);
  }
  emit_peers();
}

std::vector<PeerInfo> MeshNode::peers() const {
  const auto now = Clock::now();
  std::vector<PeerInfo> out;
  {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    out.reserve(peers_.size());
    for (const auto& [key, peer] : peers_) {
      (void)key;
      if (now - peer.last_seen <= kPeerTimeout) out.push_back(peer);
    }
  }
  std::sort(out.begin(), out.end(), [](const PeerInfo& a, const PeerInfo& b) {
    const std::string la = lower_ascii(a.name);
    const std::string lb = lower_ascii(b.name);
    if (la != lb) return la < lb;
    return a.short_fingerprint() < b.short_fingerprint();
  });
  return out;
}

void MeshNode::emit_peers() {
  if (!on_peers) return;
  on_peers(peers());
}

void MeshNode::emit_notice(const std::string& text) {
  if (on_notice) on_notice(text);
}

void MeshNode::emit_error(const std::string& text) {
  if (on_error) on_error(text);
}

std::optional<PeerInfo> MeshNode::resolve_target(const std::vector<PeerInfo>& all,
                                                 const std::string& query,
                                                 std::string& error) const {
  const std::string wanted = trim(query);
  if (wanted.empty()) {
    error = "target name is empty";
    return std::nullopt;
  }

  std::vector<PeerInfo> by_name;
  for (const auto& peer : all) {
    if (iequals(peer.name, wanted)) by_name.push_back(peer);
  }
  if (by_name.size() == 1) return by_name.front();
  if (by_name.size() > 1) {
    std::string candidates;
    for (const auto& peer : by_name) {
      if (!candidates.empty()) candidates += ", ";
      candidates += peer.name + " (" + peer.short_fingerprint() + ")";
    }
    error = "ambiguous name; use a fingerprint prefix: " + candidates;
    return std::nullopt;
  }

  const std::string fp = normalize_fingerprint(wanted);
  if (fp.size() >= 4) {
    std::vector<PeerInfo> by_fp;
    for (const auto& peer : all) {
      if (jn::fingerprint(peer.pk).rfind(fp, 0) == 0) by_fp.push_back(peer);
    }
    if (by_fp.size() == 1) return by_fp.front();
    if (by_fp.size() > 1) {
      error = "fingerprint prefix is ambiguous; use more characters";
      return std::nullopt;
    }
  }
  error = "no online peer named " + wanted;
  return std::nullopt;
}

SendOutcome MeshNode::send_message(const std::string& target, const std::string& text,
                                   int requested_relays) {
  SendOutcome outcome;
  if (text.empty()) {
    outcome.error = "message is empty";
    return outcome;
  }
  if (text.size() > kMaxText) {
    outcome.error = "message is too long (max " + std::to_string(kMaxText) + " bytes)";
    return outcome;
  }

  std::vector<PeerInfo> all = peers();
  std::string error;
  auto target_peer = resolve_target(all, target, error);
  if (!target_peer) {
    outcome.error = error;
    return outcome;
  }

  int requested = std::max(0, requested_relays);
  if (requested > static_cast<int>(kMaxRelays)) requested = static_cast<int>(kMaxRelays);

  std::vector<PeerInfo> candidates;
  for (const auto& peer : all) {
    if (peer.pk != target_peer->pk) candidates.push_back(peer);
  }
  for (std::size_t i = candidates.size(); i > 1; --i) {
    const std::uint32_t j = CryptoEngine::random_u32(static_cast<std::uint32_t>(i));
    std::swap(candidates[i - 1], candidates[j]);
  }
  const std::size_t use = std::min<std::size_t>(static_cast<std::size_t>(requested),
                                                candidates.size());

  if (requested > 0) {
    if (use == 0) {
      outcome.note = "no other online peers; sending directly";
    } else if (use < static_cast<std::size_t>(requested)) {
      outcome.note = "requested " + std::to_string(requested) + " relays, only " +
                     std::to_string(use) + " online; using " + std::to_string(use);
    }
  }

  try {
    msg::Writer writer;
    writer.map(5);
    writer.str("v");
    writer.uint(1);
    writer.str("n");
    writer.str(name_);
    writer.str("k");
    writer.bin(key_.pk.data(), key_.pk.size());
    writer.str("t");
    writer.str(text);
    writer.str("h");
    writer.uint(use);
    Bytes plain = writer.take();

    Bytes inner = CryptoEngine::box_seal(target_peer->pk, plain.data(), plain.size());
    outcome.target = target_peer->name;
    outcome.relays = use;
    outcome.direct = use == 0;
    outcome.route = name_;

    if (use == 0) {
      outcome.route += " -> " + target_peer->name;
      MeshPacket packet;
      packet.type = kDirect;
      packet.ttl = 1;
      packet.payload = std::move(inner);
      if (!send_packet(packet, Endpoint{target_peer->host, target_peer->port}, false)) {
        outcome.error = "UDP send failed; the peer may be offline";
        return outcome;
      }
      outcome.ok = true;
      return outcome;
    }

    std::string next_name = target_peer->name;
    std::string next_host = target_peer->host;
    std::uint16_t next_port = target_peer->port;
    std::uint32_t inner_type = kInnerDirect;
    std::vector<PeerInfo> relays(candidates.begin(),
                                 candidates.begin() + static_cast<std::ptrdiff_t>(use));
    for (std::size_t i = relays.size(); i-- > 0;) {
      Bytes layer = make_layer(next_name, next_host, next_port, inner_type, inner);
      Bytes sealed = CryptoEngine::box_seal(relays[i].pk, layer.data(), layer.size());
      next_name = relays[i].name;
      next_host = relays[i].host;
      next_port = relays[i].port;
      inner_type = kInnerOnion;
      inner = std::move(sealed);
    }
    if (inner.size() > kMaxPayload) {
      outcome.error = "onion is too large; reduce the message or relay count";
      return outcome;
    }

    for (const auto& relay : relays) outcome.route += " -> " + relay.name;
    outcome.route += " -> " + target_peer->name;

    MeshPacket packet;
    packet.type = kOnion;
    packet.ttl = static_cast<std::uint8_t>(use + 1);
    packet.payload = std::move(inner);
    if (!send_packet(packet, Endpoint{relays.front().host, relays.front().port}, false)) {
      outcome.error = "UDP send failed; try fewer relays or a different peer";
      return outcome;
    }
    outcome.ok = true;
    return outcome;
  } catch (const std::exception& e) {
    outcome.error = std::string("cannot build message: ") + e.what();
    return outcome;
  }
}

}  // namespace jn::mesh
