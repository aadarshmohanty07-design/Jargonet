#include "app/node.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/msgpack.hpp"
#include "net/rendezvous.hpp"
#include "net/stun.hpp"
#include "routing/onion.hpp"

namespace jn {
namespace {

using Clock = std::chrono::steady_clock;

std::string key_of(const PublicKey& pk) { return hex_encode(pk.data(), pk.size()); }
std::string sid_hex(const SessionId& sid) { return hex_encode(sid.data(), sid.size()); }

std::string sanitize_name(std::string name) {
  name = trim(name);
  std::string out;
  for (char c : name) {
    if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) out.push_back(c);
    if (out.size() >= 32) break;
  }
  if (out.empty()) out = "peer";
  return out;
}

std::string human_sid(const SessionId& sid) { return sid_hex(sid).substr(0, 12); }

}  // namespace

Node::Node(NodeConfig config, Identity identity, const std::string& password)
    : config_(std::move(config)),
      identity_(std::move(identity)),
      store_(std::make_unique<LocalStore>(config_.data_dir, password)),
      sessions_(std::make_unique<SessionManager>(identity_, *store_)),
      dispatcher_(identity_) {
  for (const auto& contact : store_->contacts()) {
    Peer peer;
    peer.pk = contact.pk;
    peer.sign_pk = contact.sign_pk;
    peer.name = sanitize_name(contact.username);
    peers_[key_of(peer.pk)] = std::move(peer);
  }
  sessions_->load_stored_sessions();
}

Node::~Node() { stop(); }

bool Node::start(std::string& error) {
  if (started_) return true;
  CryptoEngine::init();
  if (!socket_.open(config_.listen_port, error)) return false;

  if (config_.stun) {
    auto mapped = stun_discover(socket_, *config_.stun, 1500);
    if (mapped) my_endpoints_.push_back(*mapped);
  }
  if (config_.advertise && !config_.advertise->host.empty()) {
    const std::uint16_t advertised_port =
        config_.advertise->port == 0 ? socket_.local_port() : config_.advertise->port;
    my_endpoints_.insert(my_endpoints_.begin(),
                         Endpoint{config_.advertise->host, advertised_port});
  }
  for (const auto& ep : local_candidates(socket_.local_port())) {
    if (std::find(my_endpoints_.begin(), my_endpoints_.end(), ep) == my_endpoints_.end()) {
      my_endpoints_.push_back(ep);
    }
  }
  if (my_endpoints_.size() > 8) my_endpoints_.resize(8);

  if (config_.rendezvous) {
    rv_string_ = config_.rendezvous->to_string();
    rv_endpoint_ = UdpSocket::resolve_ipv4(config_.rendezvous->host,
                                           config_.rendezvous->port)
                       .value_or(*config_.rendezvous);
    register_rendezvous();
    for (auto& [key, peer] : peers_) {
      (void)key;
      discover_via_rendezvous(peer);
    }
  }

  const auto now = Clock::now();
  last_keepalive_ = now;
  last_rv_register_ = now;
  last_ratchet_check_ = now;
  started_ = true;
  emit_system("listening on UDP " + std::to_string(socket_.local_port()));
  return true;
}

void Node::stop() {
  if (!started_) {
    socket_.close();
    return;
  }
  started_ = false;
  socket_.close();
  pending_wire_.clear();
  outgoing_requests_.clear();
  incoming_requests_.clear();
}

void Node::set_mode(const std::string& mode) {
  if (mode == "auto" || mode == "direct" || mode == "onion") config_.mode = mode;
}

void Node::emit_system(const std::string& message) {
  if (on_system) on_system(message);
}

Node::Peer& Node::peer_for(const PublicKey& pk, const std::string& name) {
  auto& peer = peers_[key_of(pk)];
  if (is_zero(peer.pk)) peer.pk = pk;
  if (!name.empty()) peer.name = sanitize_name(name);
  return peer;
}

const Node::Peer* Node::find_peer(const PublicKey& pk) const {
  auto it = peers_.find(key_of(pk));
  return it == peers_.end() ? nullptr : &it->second;
}

Endpoint Node::endpoint_of(const Peer& peer) const {
  if (peer.last_endpoint.valid()) return peer.last_endpoint;
  if (!peer.endpoints.empty()) return peer.endpoints.front();
  return {};
}

void Node::add_endpoint(Peer& peer, const Endpoint& endpoint) {
  if (!endpoint.valid()) return;
  if (!peer.last_endpoint.valid()) peer.last_endpoint = endpoint;
  if (std::find(peer.endpoints.begin(), peer.endpoints.end(), endpoint) != peer.endpoints.end()) {
    return;
  }
  if (peer.endpoints.size() >= 8) peer.endpoints.erase(peer.endpoints.begin());
  peer.endpoints.push_back(endpoint);
}

void Node::mark_seen(Peer& peer, const Endpoint& endpoint) {
  const auto now = Clock::now();
  peer.last_seen = now;
  peer.last_endpoint = endpoint;
  add_endpoint(peer, endpoint);
  if (!peer.online) {
    peer.online = true;
    emit_system("peer online: " + peer.name + " (" + pretty_fingerprint(peer.pk) + ")");
  }
}

void Node::persist_contact(const Peer& peer) {
  if (is_zero(peer.pk) || peer.sign_pk == SignPublicKey{}) return;
  auto existing = store_->find_contact(peer.pk);
  if (existing && existing->username == peer.name &&
      std::equal(existing->sign_pk.begin(), existing->sign_pk.end(), peer.sign_pk.begin())) {
    return;
  }
  try {
    store_->upsert_contact(StoredContact{peer.pk, peer.sign_pk, peer.name});
  } catch (const StoreError& e) {
    emit_system(std::string("contact store: ") + e.what());
  }
}

std::optional<PublicKey> Node::peer_by_endpoint(const Endpoint& endpoint) const {
  for (const auto& [key, peer] : peers_) {
    (void)key;
    if (peer.last_endpoint == endpoint) return peer.pk;
    for (const auto& ep : peer.endpoints) {
      if (ep == endpoint) return peer.pk;
    }
  }
  return std::nullopt;
}

Bytes Node::make_sender_box(const PublicKey& recipient, const Bytes& plaintext) const {
  Bytes out(identity_.pk.begin(), identity_.pk.end());
  Bytes box = CryptoEngine::box_encrypt(recipient, identity_.sk, plaintext.data(),
                                        plaintext.size());
  out.insert(out.end(), box.begin(), box.end());
  return out;
}

std::optional<Bytes> Node::open_sender_box(const Bytes& payload, PublicKey& sender,
                                           std::string& error) const {
  if (payload.size() < kPublicKeyBytes + kNonceBytes + 16) {
    error = "sender box too short";
    return std::nullopt;
  }
  std::copy(payload.begin(), payload.begin() + kPublicKeyBytes, sender.begin());
  if (is_zero(sender) || sender == identity_.pk || !CryptoEngine::valid_public_key(sender)) {
    error = "invalid sender public key";
    return std::nullopt;
  }
  try {
    return CryptoEngine::box_decrypt(sender, identity_.sk, payload.data() + kPublicKeyBytes,
                                     payload.size() - kPublicKeyBytes);
  } catch (const CryptoError& e) {
    error = e.what();
    return std::nullopt;
  }
}

void Node::send_packet(const Packet& packet, const Endpoint& endpoint) {
  try {
    socket_.send_to(endpoint, serialize_packet(packet));
  } catch (const PacketError&) {
    ++stats_.dropped;
  }
}

void Node::send_wire(const Bytes& wire, const Endpoint& endpoint) {
  socket_.send_to(endpoint, wire);
}

void Node::send_ack(const Endpoint& endpoint, std::uint64_t msg_id) {
  Packet ack;
  ack.type = PacketType::Ack;
  ack.msg_id = msg_id;
  send_packet(ack, endpoint);
}

bool Node::track_reliable(const Packet& packet, const Endpoint& endpoint) {
  Bytes wire;
  try {
    wire = serialize_packet(packet);
  } catch (const PacketError&) {
    return false;
  }
  pending_wire_[packet.msg_id] = PendingWire{wire, endpoint, 1, Clock::now() + std::chrono::seconds(3)};
  return socket_.send_to(endpoint, wire);
}

void Node::send_hello(Peer& peer) {
  if (is_zero(peer.pk) || peer.endpoints.empty()) return;
  const auto now = Clock::now();
  if (peer.last_hello_sent.time_since_epoch().count() != 0 &&
      now - peer.last_hello_sent < std::chrono::seconds(5)) {
    return;
  }
  try {
    msg::Writer writer;
    writer.map(5);
    writer.str("v");
    writer.uint(1);
    writer.str("spk");
    writer.bin(identity_.sign_pk.data(), identity_.sign_pk.size());
    writer.str("n");
    writer.str(identity_.username);
    writer.str("relay");
    writer.boolean(config_.relay_enabled);
    writer.str("port");
    writer.uint(socket_.local_port());
    Bytes plain = writer.take();
    Bytes payload = make_sender_box(peer.pk, plain);

    Packet hello;
    hello.type = PacketType::Hello;
    hello.msg_id = new_message_id();
    hello.payload = std::move(payload);

    std::size_t attempts = 0;
    for (const auto& ep : peer.endpoints) {
      if (attempts++ >= 3) break;
      send_packet(hello, ep);
    }
    peer.last_hello_sent = now;
  } catch (const CryptoError&) {
    // Degenerate peer key; ignore.
  }
}

void Node::send_hello_to_endpoints(Peer& peer) { send_hello(peer); }

void Node::discover_via_rendezvous(const Peer& peer) {
  if (!config_.rendezvous || is_zero(peer.pk)) return;
  if (peer.last_lookup.time_since_epoch().count() != 0 &&
      Clock::now() - peer.last_lookup < std::chrono::seconds(40)) {
    return;
  }
  const std::uint64_t id = new_message_id();
  rv_lookups_[id] = peer.pk;
  auto it = peers_.find(key_of(peer.pk));
  if (it != peers_.end()) it->second.last_lookup = Clock::now();
  socket_.send_to(rv_endpoint_, make_lookup(rendezvous_tag(peer.pk), id));
}

void Node::register_rendezvous() {
  if (!config_.rendezvous) return;
  for (const auto& tag : current_rendezvous_tags(identity_.pk)) {
    socket_.send_to(rv_endpoint_, make_register(tag, 120, new_message_id()));
  }
  last_rv_register_ = Clock::now();
}

void Node::handle_datagram(const Datagram& datagram) {
  if (datagram.data.size() >= kRendezvousHeaderBytes &&
      std::memcmp(datagram.data.data(), kRendezvousMagic, kRendezvousHeaderBytes) == 0) {
    handle_rendezvous(datagram);
    return;
  }
  try {
    Packet packet = parse_packet(datagram.data);
    handle_packet(packet, datagram.from);
  } catch (const PacketError&) {
    ++stats_.dropped;
  }
}

void Node::handle_packet(const Packet& packet, const Endpoint& from) {
  switch (packet.type) {
    case PacketType::Hello:
      handle_hello(packet, from);
      break;
    case PacketType::ChatRequest:
      handle_chat_request(packet, from);
      break;
    case PacketType::ChatAccept:
      handle_chat_accept(packet, from);
      break;
    case PacketType::Direct:
      handle_direct(packet, from);
      break;
    case PacketType::OnionData:
      handle_onion(packet, from);
      break;
    case PacketType::Ratchet:
      handle_ratchet(packet, from);
      break;
    case PacketType::Ack:
      handle_ack(packet, from);
      break;
    case PacketType::Ping:
    case PacketType::Pong:
    case PacketType::Discovery:
    case PacketType::RelayAnnounce:
    case PacketType::Punch:
      break;
  }
}

void Node::handle_hello(const Packet& packet, const Endpoint& from) {
  PublicKey sender;
  std::string error;
  auto plain = open_sender_box(packet.payload, sender, error);
  if (!plain) {
    ++stats_.dropped;
    return;
  }
  try {
    msg::Value root = msg::decode(*plain);
    if (root.at("v").as_uint() != 1) return;
    const Bytes& spk = root.at("spk").as_bin();
    if (spk.size() != kSignPublicKeyBytes) return;
    SignPublicKey sign_pk{};
    std::copy(spk.begin(), spk.end(), sign_pk.begin());
    if (is_zero(sign_pk)) return;
    const std::string name = sanitize_name(root.has("n") ? root.at("n").as_str() : "peer");
    const bool relay = root.has("relay") ? root.at("relay").as_bool() : true;

    Peer& peer = peer_for(sender, name);
    peer.sign_pk = sign_pk;
    peer.relay = relay;
    mark_seen(peer, from);
    persist_contact(peer);

    if (peer.last_hello_sent.time_since_epoch().count() == 0 ||
        Clock::now() - peer.last_hello_sent >= std::chrono::seconds(5)) {
      send_hello(peer);
    }
  } catch (const msg::Error&) {
    ++stats_.dropped;
  }
}

void Node::handle_chat_request(const Packet& packet, const Endpoint& from) {
  PublicKey sender;
  std::string error;
  auto plain = open_sender_box(packet.payload, sender, error);
  if (!plain) {
    ++stats_.dropped;
    return;
  }
  try {
    msg::Value root = msg::decode(*plain);
    if (root.at("v").as_uint() != 1) return;
    const Bytes& eph = root.at("eph").as_bin();
    const Bytes& spk = root.at("spk").as_bin();
    if (eph.size() != kPublicKeyBytes || spk.size() != kSignPublicKeyBytes) return;
    IncomingRequest request;
    request.peer = sender;
    std::copy(eph.begin(), eph.end(), request.ephemeral_pk.begin());
    std::copy(spk.begin(), spk.end(), request.sign_pk.begin());
    request.name = sanitize_name(root.has("n") ? root.at("n").as_str() : "peer");
    request.endpoint = from;
    request.received = Clock::now();
    if (is_zero(request.sign_pk) || !CryptoEngine::valid_public_key(request.ephemeral_pk)) {
      ++stats_.dropped;
      return;
    }

    Peer& peer = peer_for(sender, request.name);
    peer.sign_pk = request.sign_pk;
    mark_seen(peer, from);
    persist_contact(peer);

    if (incoming_requests_.size() >= 64 && incoming_requests_.find(key_of(sender)) ==
                                               incoming_requests_.end()) {
      ++stats_.dropped;
      return;
    }
    incoming_requests_[key_of(sender)] = request;
    send_ack(from, packet.msg_id);

    PendingRequestInfo info;
    info.pk = sender;
    info.name = request.name;
    info.fingerprint = pretty_fingerprint(sender);
    if (on_request) on_request(info);
    emit_system("chat request from " + request.name + " (" + pretty_fingerprint(sender) + ")");
    if (config_.auto_accept) {
      std::string message;
      accept_incoming(sender, message);
    }
  } catch (const msg::Error&) {
    ++stats_.dropped;
  }
}

bool Node::accept_incoming(const PublicKey& pk, std::string& message) {
  auto it = incoming_requests_.find(key_of(pk));
  if (it == incoming_requests_.end()) {
    message = "no pending chat request from that peer";
    return false;
  }
  const IncomingRequest request = it->second;
  try {
    auto ephemeral = CryptoEngine::generate_box_keypair();
    DerivedSession keys = derive_session(false, identity_.pk, identity_.sk, request.peer,
                                          ephemeral.sk, request.ephemeral_pk);

    Session session;
    session.sid = keys.sid;
    session.peer_pk = request.peer;
    session.peer_sign_pk = request.sign_pk;
    session.peer_name = request.name;
    session.label = request.name;
    session.initiator = false;
    session.key_i2r = std::move(keys.i2r);
    session.key_r2i = std::move(keys.r2i);
    session.epoch = 0;
    session.messages_since_ratchet = 0;
    session.established = Clock::now();
    session.last_ratchet = session.established;
    session.ratchet_leader = false;

    msg::Writer writer;
    writer.map(6);
    writer.str("v");
    writer.uint(1);
    writer.str("pk");
    writer.bin(identity_.pk.data(), identity_.pk.size());
    writer.str("spk");
    writer.bin(identity_.sign_pk.data(), identity_.sign_pk.size());
    writer.str("n");
    writer.str(identity_.username);
    writer.str("eph");
    writer.bin(ephemeral.pk.data(), ephemeral.pk.size());
    writer.str("sid");
    writer.bin(keys.sid.data(), keys.sid.size());
    Bytes plain = writer.take();

    Packet accept;
    accept.type = PacketType::ChatAccept;
    accept.msg_id = new_message_id();
    accept.payload = make_sender_box(request.peer, plain);

    Session* added = sessions_->add(std::move(session));
    track_reliable(accept, request.endpoint);
    incoming_requests_.erase(it);
    message = "accepted chat with " + request.name;
    if (added) notify_session(*added);
    emit_system(message + " (session " + human_sid(added->sid) + ")");
    return true;
  } catch (const CryptoError& e) {
    message = std::string("session setup failed: ") + e.what();
    return false;
  }
}

void Node::handle_chat_accept(const Packet& packet, const Endpoint& from) {
  PublicKey sender;
  std::string error;
  auto plain = open_sender_box(packet.payload, sender, error);
  if (!plain) {
    ++stats_.dropped;
    return;
  }
  auto request_it = outgoing_requests_.find(key_of(sender));
  if (request_it == outgoing_requests_.end()) {
    send_ack(from, packet.msg_id);
    return;
  }
  try {
    msg::Value root = msg::decode(*plain);
    if (root.at("v").as_uint() != 1) return;
    if (root.at("pk").as_public_key() != sender) return;
    const Bytes& eph = root.at("eph").as_bin();
    const Bytes& spk = root.at("spk").as_bin();
    if (eph.size() != kPublicKeyBytes || spk.size() != kSignPublicKeyBytes) return;
    PublicKey peer_eph{};
    std::copy(eph.begin(), eph.end(), peer_eph.begin());
    SignPublicKey peer_sign{};
    std::copy(spk.begin(), spk.end(), peer_sign.begin());
    if (is_zero(peer_sign) || !CryptoEngine::valid_public_key(peer_eph)) return;

    const SessionId claimed_sid = root.at("sid").as_session_id();
    DerivedSession keys = derive_session(true, identity_.pk, identity_.sk, sender,
                                          request_it->second.ephemeral.sk, peer_eph);
    if (keys.sid != claimed_sid) {
      emit_system("session confirmation failed (id mismatch)");
      ++stats_.dropped;
      return;
    }

    Session session;
    session.sid = keys.sid;
    session.peer_pk = sender;
    session.peer_sign_pk = peer_sign;
    session.peer_name = sanitize_name(root.has("n") ? root.at("n").as_str() : request_it->second.name);
    session.label = session.peer_name;
    session.initiator = true;
    session.ratchet_leader = true;
    session.key_i2r = std::move(keys.i2r);
    session.key_r2i = std::move(keys.r2i);
    session.established = Clock::now();
    session.last_ratchet = session.established;

    Session* added = sessions_->add(std::move(session));
    Peer& peer = peer_for(sender, added->peer_name);
    peer.sign_pk = peer_sign;
    mark_seen(peer, from);
    persist_contact(peer);

    outgoing_requests_.erase(request_it);
    send_ack(from, packet.msg_id);
    if (added) notify_session(*added);
    emit_system("chat accepted by " + peer.name + " (session " + human_sid(added->sid) + ")");
  } catch (const msg::Error&) {
    ++stats_.dropped;
  } catch (const CryptoError& e) {
    emit_system(std::string("accept failed: ") + e.what());
  }
}

void Node::handle_direct(const Packet& packet, const Endpoint& from) {
  Session* session = sessions_->by_id(packet.session);
  if (!session) {
    ++stats_.dropped;
    return;
  }
  std::string error;
  auto payload = dispatcher_.open(*session, packet, error);
  if (!payload) {
    ++stats_.dropped;
    return;
  }
  if (payload->from_pk == identity_.pk) return;
  const bool onion = (packet.flags & kFlagOnionDelivered) != 0;

  if (session->group) {
    bool known = false;
    for (const auto& member : session->members) {
      if (member.pk == payload->from_pk) {
        known = true;
        if (!std::equal(member.sign_pk.begin(), member.sign_pk.end(),
                        payload->sign_pk.begin())) {
          ++stats_.dropped;
          return;
        }
        break;
      }
    }
    if (!known) {
      GroupMember member{payload->from_pk, payload->sign_pk, payload->from_name};
      sessions_->add_member(*session, member);
      if (!onion) {
        Peer& peer = peer_for(payload->from_pk, payload->from_name);
        peer.sign_pk = payload->sign_pk;
        mark_seen(peer, from);
        persist_contact(peer);
      }
    }
  }

  if (seen_message(packet.session, packet.msg_id)) {
    if (!onion) send_ack(from, packet.msg_id);
    return;
  }

  if (!session->group) {
    Peer& peer = peer_for(payload->from_pk);
    if (!onion) mark_seen(peer, from);
    if (peer.name.empty()) peer.name = payload->from_name;
  } else if (!onion) {
    Peer& peer = peer_for(payload->from_pk, payload->from_name);
    mark_seen(peer, from);
  }

  sessions_->note_message(*session);

  StoredMessage stored;
  stored.sid = session->sid;
  stored.from_pk = payload->from_pk;
  stored.from_name = payload->from_name;
  stored.outgoing = false;
  stored.text = payload->text;
  stored.seq = payload->seq;
  try {
    store_->append_message(stored);
  } catch (const StoreError& e) {
    emit_system(std::string("store: ") + e.what());
  }

  IncomingMessage incoming;
  incoming.sid = session->sid;
  incoming.session_label = session->label;
  incoming.from_pk = payload->from_pk;
  incoming.from_name = payload->from_name;
  incoming.text = payload->text;
  incoming.group = session->group;
  incoming.kind = payload->kind;
  incoming.onion = onion;
  if (on_message) on_message(incoming);

  if (!onion) send_ack(from, packet.msg_id);
}

void Node::handle_onion(const Packet& packet, const Endpoint& from) {
  (void)from;
  if (seen_onion(packet.payload)) {
    ++stats_.dropped;
    return;
  }
  PeeledLayer layer = OnionRouter::peel(identity_.pk, identity_.sk, packet.payload);
  switch (layer.kind) {
    case PeeledLayer::Kind::Relay: {
      if (packet.ttl == 0) {
        ++stats_.dropped;
        return;
      }
      Packet forward;
      forward.type = PacketType::OnionData;
      forward.ttl = static_cast<std::uint8_t>(packet.ttl - 1);
      forward.session = random_session_id();
      forward.msg_id = new_message_id();
      forward.payload = std::move(layer.inner);
      send_packet(forward, layer.endpoint);
      ++stats_.relayed;
      break;
    }
    case PeeledLayer::Kind::Deliver:
      send_wire(layer.inner, layer.endpoint);
      ++stats_.delivered;
      break;
    default:
      ++stats_.dropped;
      break;
  }
}

void Node::handle_ratchet(const Packet& packet, const Endpoint& from) {
  Session* session = sessions_->by_id(packet.session);
  if (!session) {
    ++stats_.dropped;
    return;
  }
  std::string error;
  if (!sessions_->handle_ratchet(*session, packet.payload, error)) {
    ++stats_.dropped;
    return;
  }
  send_ack(from, packet.msg_id);
  emit_system("session keys rotated with " + session->label + " (epoch " +
              std::to_string(session->epoch) + ")");
}

void Node::handle_ack(const Packet& packet, const Endpoint& from) {
  auto it = pending_wire_.find(packet.msg_id);
  if (it != pending_wire_.end() && it->second.dest == from) {
    pending_wire_.erase(it);
  }
  for (auto& [key, request] : outgoing_requests_) {
    (void)key;
    if (request.msg_id == packet.msg_id && request.endpoint == from) {
      request.attempts = 3;
    }
  }
}

void Node::handle_rendezvous(const Datagram& datagram) {
  if (!config_.rendezvous || datagram.from != rv_endpoint_) return;
  auto value = decode_rendezvous(datagram.data);
  if (!value) return;
  const msg::Value* type = value->find("t");
  if (!type || type->type != msg::Value::Type::Str || type->str != "peers") return;
  const msg::Value* id_value = value->find("id");
  if (!id_value) return;
  std::uint64_t id = 0;
  try {
    id = id_value->as_uint();
  } catch (const msg::Error&) {
    return;
  }
  auto lookup = rv_lookups_.find(id);
  if (lookup == rv_lookups_.end()) return;
  const PublicKey pk = lookup->second;
  rv_lookups_.erase(lookup);

  auto endpoints = parse_peer_list(*value);
  Peer& peer = peer_for(pk);
  for (const auto& ep : endpoints) add_endpoint(peer, ep);
  if (!endpoints.empty()) send_hello(peer);
}

void Node::run_once(int timeout_ms) {
  if (!started_) return;
  if (socket_.wait_readable(timeout_ms)) {
    for (int i = 0; i < 256; ++i) {
      auto datagram = socket_.recv_from();
      if (!datagram) break;
      handle_datagram(*datagram);
    }
  }
  process_timers();
}

void Node::process_timers() {
  const auto now = Clock::now();
  retry_pending();
  if (now - last_keepalive_ >= std::chrono::seconds(20)) {
    last_keepalive_ = now;
    send_keepalives();
  }
  if (config_.rendezvous) {
    if (now - last_rv_register_ >= std::chrono::seconds(60)) register_rendezvous();
    for (auto& [key, peer] : peers_) {
      (void)key;
      if (!peer.online || peer.endpoints.empty()) discover_via_rendezvous(peer);
    }
  }
  maybe_ratchet();
  maybe_send_group_join();
  sessions_->tick();
  expire_seen();
}

void Node::retry_pending() {
  const auto now = Clock::now();
  for (auto it = pending_wire_.begin(); it != pending_wire_.end();) {
    if (now < it->second.next_retry) {
      ++it;
      continue;
    }
    if (it->second.attempts >= 3) {
      it = pending_wire_.erase(it);
      continue;
    }
    socket_.send_to(it->second.dest, it->second.wire);
    ++it->second.attempts;
    it->second.next_retry = now + std::chrono::seconds(3);
    ++it;
  }

  for (auto it = outgoing_requests_.begin(); it != outgoing_requests_.end();) {
    if (now >= it->second.expires) {
      emit_system("chat request to " + it->second.name + " expired");
      it = outgoing_requests_.erase(it);
      continue;
    }
    if (it->second.attempts < 3 && now >= it->second.next_retry) {
      socket_.send_to(it->second.endpoint, it->second.wire);
      ++it->second.attempts;
      it->second.next_retry = now + std::chrono::seconds(3);
    }
    ++it;
  }
}

void Node::send_keepalives() {
  const auto now = Clock::now();
  for (auto& [key, peer] : peers_) {
    (void)key;
    if (peer.endpoints.empty()) continue;
    if (peer.online && now - peer.last_seen > std::chrono::seconds(90)) {
      peer.online = false;
    }
    send_hello(peer);
  }
}

void Node::maybe_ratchet() {
  const auto now = Clock::now();
  if (now - last_ratchet_check_ < std::chrono::seconds(1)) return;
  last_ratchet_check_ = now;

  for (Session* session : sessions_->active_sessions()) {
    if (session->group || !session->initiator) continue;
    RatchetUpdate update;
    if (!sessions_->rotate_if_due(*session, update)) continue;
    const Peer* peer = find_peer(session->peer_pk);
    if (!peer) continue;
    const Endpoint ep = endpoint_of(*peer);
    if (!ep.valid()) continue;

    Packet packet;
    packet.type = PacketType::Ratchet;
    packet.session = session->sid;
    packet.msg_id = new_message_id();
    packet.payload = update.control_payload;
    try {
      Bytes wire = serialize_packet(packet);
      if (!socket_.send_to(ep, wire)) continue;
      pending_wire_[packet.msg_id] =
          PendingWire{wire, ep, 1, now + std::chrono::seconds(3)};
    } catch (const PacketError&) {
      continue;
    }
    commit_ratchet(*session, std::move(update), now);
    emit_system("rotated session keys with " + session->label);
  }
}

bool Node::send_join_notice(Session& session) {
  if (!session.group) return false;
  if (notified_joins_.count(sid_hex(session.sid))) return true;
  std::uint64_t msg_id = new_message_id();
  std::uint64_t seq = session.next_seq;
  std::string error;
  const std::size_t sent = send_group_message(session, "joined", ChatKind::Join, msg_id, seq,
                                              error, true);
  if (sent > 0) {
    ++session.next_seq;
    notified_joins_.insert(sid_hex(session.sid));
    return true;
  }
  return false;
}

void Node::maybe_send_group_join() {
  const auto now = Clock::now();
  for (Session* session : sessions_->active_sessions()) {
    if (!session->group) continue;
    const std::string key = sid_hex(session->sid);
    if (notified_joins_.count(key)) continue;
    auto it = join_attempts_.find(key);
    if (it != join_attempts_.end() && now - it->second < std::chrono::seconds(5)) continue;
    join_attempts_[key] = now;
    send_join_notice(*session);
  }
}

void Node::expire_seen() {
  const auto now = Clock::now();
  auto prune = [&](std::unordered_set<std::string>& set,
                   std::deque<SeenEntry>& order) {
    while (!order.empty() &&
           (order.front().when + std::chrono::minutes(10) < now || order.size() > 4096)) {
      set.erase(order.front().key);
      order.pop_front();
    }
  };
  prune(seen_messages_, seen_message_order_);
  prune(seen_onions_, seen_onion_order_);
}

bool Node::seen_message(const SessionId& sid, std::uint64_t msg_id) {
  std::string key = sid_hex(sid) + ":" + hex_encode(reinterpret_cast<const std::uint8_t*>(&msg_id),
                                                    sizeof(msg_id));
  if (!seen_messages_.insert(key).second) return true;
  seen_message_order_.push_back(SeenEntry{key, Clock::now()});
  return false;
}

bool Node::seen_onion(const Bytes& payload) {
  Bytes digest = CryptoEngine::hash(payload, 16);
  std::string key = hex_encode(digest);
  if (!seen_onions_.insert(key).second) return true;
  seen_onion_order_.push_back(SeenEntry{key, Clock::now()});
  return false;
}

std::vector<PeerInfo> Node::peers() const {
  const auto now = Clock::now();
  std::vector<PeerInfo> out;
  for (const auto& [key, peer] : peers_) {
    (void)key;
    PeerInfo info;
    info.pk = peer.pk;
    info.sign_pk = peer.sign_pk;
    info.name = peer.name.empty() ? "(unknown)" : peer.name;
    info.fingerprint = pretty_fingerprint(peer.pk);
    info.endpoint = endpoint_of(peer);
    info.online = peer.last_seen.time_since_epoch().count() != 0 &&
                  now - peer.last_seen < std::chrono::seconds(90);
    info.relay = peer.relay;
    out.push_back(std::move(info));
  }
  std::sort(out.begin(), out.end(), [](const PeerInfo& a, const PeerInfo& b) {
    if (a.online != b.online) return a.online > b.online;
    return a.name < b.name;
  });
  return out;
}

std::vector<PendingRequestInfo> Node::requests() const {
  std::vector<PendingRequestInfo> out;
  for (const auto& [key, request] : incoming_requests_) {
    (void)key;
    PendingRequestInfo info;
    info.pk = request.peer;
    info.name = request.name;
    info.fingerprint = pretty_fingerprint(request.peer);
    out.push_back(std::move(info));
  }
  std::sort(out.begin(), out.end(),
            [](const PendingRequestInfo& a, const PendingRequestInfo& b) {
              return a.name < b.name;
            });
  return out;
}

std::vector<SessionView> Node::session_views() const { return sessions_->views(); }

std::vector<StoredMessage> Node::history(const SessionId& sid, std::size_t limit) const {
  return store_->messages(sid, limit);
}

std::optional<PublicKey> Node::resolve_peer(const std::string& query) const {
  const std::string q = trim(query);
  if (q.empty()) return std::nullopt;
  auto list = peers();
  bool numeric = std::all_of(q.begin(), q.end(), [](unsigned char c) { return std::isdigit(c); });
  if (numeric) {
    const auto index = static_cast<std::size_t>(std::stoul(q));
    if (index >= 1 && index <= list.size()) return list[index - 1].pk;
  }
  std::string fp_query;
  for (char c : q) {
    if (c != '-' && c != ' ') fp_query.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  for (const auto& peer : list) {
    if (jn::fingerprint(peer.pk).rfind(fp_query, 0) == 0) return peer.pk;
  }
  for (const auto& peer : list) {
    if (iequals(peer.name, q)) return peer.pk;
  }
  return std::nullopt;
}

std::optional<SessionId> Node::resolve_session(const std::string& query) const {
  const std::string q = trim(query);
  if (q.empty()) return std::nullopt;
  auto list = session_views();
  bool numeric = std::all_of(q.begin(), q.end(), [](unsigned char c) { return std::isdigit(c); });
  if (numeric) {
    const auto index = static_cast<std::size_t>(std::stoul(q));
    if (index >= 1 && index <= list.size()) return list[index - 1].sid;
  }
  for (const auto& view : list) {
    if (sid_hex(view.sid).rfind(q, 0) == 0 || view.label == q) return view.sid;
  }
  for (const auto& view : list) {
    if (iequals(view.label, q)) return view.sid;
  }
  return std::nullopt;
}

bool Node::add_contact(const std::string& invite_code, std::string& error) {
  auto invite = decode_contact_invite(invite_code, error);
  if (!invite) return false;
  if (invite->pk == identity_.pk) {
    error = "that is your own invite";
    return false;
  }
  Peer& peer = peer_for(invite->pk, invite->username);
  peer.sign_pk = invite->sign_pk;
  for (const auto& ep : invite->endpoints) add_endpoint(peer, ep);
  if (peer.endpoints.empty()) {
    error = config_.rendezvous
                ? "contact added; waiting for rendezvous discovery"
                : "contact added, but the invite has no endpoint hint and no rendezvous server is configured";
  } else {
    error.clear();
  }
  persist_contact(peer);
  send_hello(peer);
  discover_via_rendezvous(peer);
  if (on_system) on_system("contact added: " + peer.name + " (" + pretty_fingerprint(peer.pk) + ")");
  return true;
}

bool Node::request_chat(const std::string& peer_query, std::string& message) {
  auto pk = resolve_peer(peer_query);
  if (!pk) {
    message = "unknown peer; use /add <invite> and /peers";
    return false;
  }
  if (Session* existing = sessions_->active_with(*pk)) {
    message = "already have an active session (" + human_sid(existing->sid) + ")";
    notify_session(*existing);
    return true;
  }
  Peer& peer = peer_for(*pk);
  Endpoint endpoint = endpoint_of(peer);
  if (!endpoint.valid()) {
    discover_via_rendezvous(peer);
    message = "peer is not reachable yet; try again when they are online";
    return false;
  }
  if (outgoing_requests_.size() >= 64) {
    message = "too many pending chat requests";
    return false;
  }

  try {
    OutgoingRequest request;
    request.peer = *pk;
    request.name = peer.name;
    request.ephemeral = CryptoEngine::generate_box_keypair();
    request.endpoint = endpoint;
    request.msg_id = new_message_id();
    request.expires = Clock::now() + std::chrono::seconds(60);
    request.next_retry = Clock::now() + std::chrono::seconds(3);
    request.attempts = 1;

    msg::Writer writer;
    writer.map(4);
    writer.str("v");
    writer.uint(1);
    writer.str("spk");
    writer.bin(identity_.sign_pk.data(), identity_.sign_pk.size());
    writer.str("n");
    writer.str(identity_.username);
    writer.str("eph");
    writer.bin(request.ephemeral.pk.data(), request.ephemeral.pk.size());
    Bytes plain = writer.take();

    Packet packet;
    packet.type = PacketType::ChatRequest;
    packet.msg_id = request.msg_id;
    packet.payload = make_sender_box(*pk, plain);
    request.wire = serialize_packet(packet);
    socket_.send_to(endpoint, request.wire);

    const std::string key = key_of(*pk);
    outgoing_requests_[key] = std::move(request);
    message = "chat request sent to " + peer.name + "; waiting for acceptance";
    return true;
  } catch (const std::exception& e) {
    message = std::string("cannot send chat request: ") + e.what();
    return false;
  }
}

bool Node::accept_chat(const std::string& peer_query, std::string& message) {
  auto pk = resolve_peer(peer_query);
  if (!pk) {
    message = "unknown peer";
    return false;
  }
  return accept_incoming(*pk, message);
}

bool Node::decline_chat(const std::string& peer_query, std::string& message) {
  auto pk = resolve_peer(peer_query);
  if (!pk) {
    message = "unknown peer";
    return false;
  }
  auto it = incoming_requests_.find(key_of(*pk));
  if (it == incoming_requests_.end()) {
    message = "no pending chat request from that peer";
    return false;
  }
  incoming_requests_.erase(it);
  message = "chat request declined";
  return true;
}

std::vector<OnionHop> Node::relay_candidates(const PublicKey& recipient) const {
  const auto now = Clock::now();
  std::vector<OnionHop> out;
  for (const auto& [key, peer] : peers_) {
    (void)key;
    if (peer.pk == identity_.pk || peer.pk == recipient) continue;
    if (!peer.relay || !peer.online) continue;
    if (peer.last_seen.time_since_epoch().count() == 0 ||
        now - peer.last_seen > std::chrono::seconds(90)) {
      continue;
    }
    Endpoint ep = endpoint_of(peer);
    if (!ep.valid()) continue;
    out.push_back(OnionHop{peer.pk, ep});
  }
  return out;
}

bool Node::send_group_message(Session& session, const std::string& text, ChatKind kind,
                              std::uint64_t msg_id, std::uint64_t seq, std::string& error,
                              bool join_notice) {
  (void)join_notice;
  try {
    Packet direct = dispatcher_.build_direct(session, kind, text, msg_id, seq, 0);
    Bytes direct_wire = serialize_packet(direct);
    std::size_t sent = 0;

    for (const auto& member : session.members) {
      if (member.pk == identity_.pk) continue;
      const Peer* peer = find_peer(member.pk);
      if (!peer) continue;
      Endpoint endpoint = endpoint_of(*peer);
      if (!endpoint.valid()) continue;

      auto path = relay_candidates(member.pk);
      const bool want_onion =
          config_.mode == "onion" ||
          (config_.mode == "auto" && path.size() >= static_cast<std::size_t>(config_.onion_min_hops));
      if (want_onion) {
        auto selected = OnionRouter::select_path(path, identity_.pk, member.pk,
                                                 config_.onion_min_hops, config_.onion_max_hops);
        if (!selected.empty()) {
          std::string onion_error;
          auto built = OnionRouter::build(selected, endpoint, direct_wire, onion_error);
          if (built) {
            Packet onion;
            onion.type = PacketType::OnionData;
            onion.ttl = static_cast<std::uint8_t>(selected.size());
            onion.session = random_session_id();
            onion.msg_id = new_message_id();
            onion.payload = built->payload;
            send_packet(onion, built->first_hop);
            ++stats_.onion_sent;
            ++sent;
            continue;
          }
        }
        if (config_.mode == "onion") continue;
      }
      if (socket_.send_to(endpoint, direct_wire)) {
        ++stats_.direct_sent;
        ++sent;
      }
    }

    if (sent == 0) {
      error = "no group member is currently reachable";
      return false;
    }
    return true;
  } catch (const std::exception& e) {
    error = e.what();
    return false;
  }
}

bool Node::send_text(const SessionId& sid, const std::string& text, std::string& error,
                     bool* used_onion, std::size_t* relay_count) {
  if (used_onion) *used_onion = false;
  if (relay_count) *relay_count = 0;
  Session* session = sessions_->by_id(sid);
  if (!session) {
    error = "session is not active; start a new chat with /chat";
    return false;
  }
  const std::string message = trim(text);
  if (message.empty()) {
    error = "message is empty";
    return false;
  }
  if (message.size() > 320) {
    error = "message is too long (max 320 bytes)";
    return false;
  }

  const std::uint64_t seq = session->next_seq;
  const std::uint64_t msg_id = new_message_id();

  if (session->group) {
    if (!send_group_message(*session, message, ChatKind::Chat, msg_id, seq, error, false)) {
      return false;
    }
    ++session->next_seq;
    StoredMessage stored;
    stored.sid = sid;
    stored.from_pk = identity_.pk;
    stored.from_name = identity_.username;
    stored.outgoing = true;
    stored.text = message;
    stored.seq = seq;
    try {
      store_->append_message(stored);
    } catch (const StoreError& e) {
      error = e.what();
      return false;
    }
    if (used_onion) *used_onion = config_.mode == "onion";
    if (relay_count) *relay_count = 0;
    return true;
  }

  const Peer* peer = find_peer(session->peer_pk);
  if (!peer) {
    error = "peer is not known";
    return false;
  }
  Endpoint endpoint = endpoint_of(*peer);
  if (!endpoint.valid()) {
    error = "peer has no reachable endpoint";
    return false;
  }

  auto candidates = relay_candidates(session->peer_pk);
  bool use_onion = false;
  if (config_.mode == "onion") {
    if (candidates.size() < static_cast<std::size_t>(config_.onion_min_hops)) {
      error = "onion mode needs at least " + std::to_string(config_.onion_min_hops) +
              " online relay peers";
      return false;
    }
    use_onion = true;
  } else if (config_.mode == "auto") {
    use_onion = candidates.size() >= static_cast<std::size_t>(config_.onion_min_hops);
  }

  try {
    if (use_onion) {
      auto selected = OnionRouter::select_path(candidates, identity_.pk, session->peer_pk,
                                               config_.onion_min_hops, config_.onion_max_hops);
      if (selected.empty()) {
        error = "could not select a relay path";
        return false;
      }
      std::string onion_error;
      auto built = dispatcher_.build_onion(*session, ChatKind::Chat, message, msg_id, seq,
                                           endpoint, selected, onion_error);
      if (!built) {
        error = "cannot build onion: " + onion_error;
        return false;
      }
      Packet onion;
      onion.type = PacketType::OnionData;
      onion.ttl = static_cast<std::uint8_t>(selected.size());
      onion.session = random_session_id();
      onion.msg_id = new_message_id();
      onion.payload = built->payload;
      send_packet(onion, built->first_hop);
      ++stats_.onion_sent;
      if (used_onion) *used_onion = true;
      if (relay_count) *relay_count = selected.size();
    } else {
      Packet direct = dispatcher_.build_direct(*session, ChatKind::Chat, message, msg_id, seq, 0);
      if (!track_reliable(direct, endpoint)) {
        error = "UDP send failed";
        return false;
      }
      ++stats_.direct_sent;
    }
  } catch (const std::exception& e) {
    error = e.what();
    return false;
  }

  ++session->next_seq;
  sessions_->note_message(*session);

  StoredMessage stored;
  stored.sid = sid;
  stored.from_pk = identity_.pk;
  stored.from_name = identity_.username;
  stored.outgoing = true;
  stored.text = message;
  stored.seq = seq;
  try {
    store_->append_message(stored);
  } catch (const StoreError& e) {
    error = e.what();
    return false;
  }
  return true;
}

std::string Node::create_group(const std::string& label, std::string& error) {
  std::string clean = sanitize_name(label);
  if (clean == "peer") clean = "group";

  Session session;
  session.sid = random_session_id();
  while (sessions_->by_id(session.sid) != nullptr) session.sid = random_session_id();
  SecureBuffer key = CryptoEngine::random_bytes(32);
  session.key_i2r = SecureBuffer(key.data(), key.size());
  session.key_r2i = SecureBuffer(key.data(), key.size());
  session.group = true;
  session.initiator = true;
  session.peer_pk = kZeroPublicKey;
  session.peer_sign_pk = SignPublicKey{};
  session.label = clean;
  session.peer_name = clean;
  session.established = Clock::now();
  session.last_ratchet = session.established;

  Session* added = sessions_->add(std::move(session));
  if (!added) {
    error = "could not create group";
    return {};
  }
  notify_session(*added);
  return group_invite(added->sid, error);
}

std::string Node::group_invite(const SessionId& sid, std::string& error) const {
  const Session* session = sessions_->by_id(sid);
  if (!session || !session->group) {
    error = "session is not an active group";
    return {};
  }
  GroupInvite invite;
  invite.sid = session->sid;
  invite.group_key = session->key_i2r.copy_bytes();
  invite.label = session->label;
  invite.creator_pk = identity_.pk;
  invite.creator_sign_pk = identity_.sign_pk;
  invite.creator_name = identity_.username;
  invite.endpoints = my_endpoints_;
  invite.rendezvous = rv_string_;
  return encode_group_invite(invite);
}

bool Node::join_group(const std::string& invite_code, SessionId& joined, std::string& error) {
  auto invite = decode_group_invite(invite_code, error);
  if (!invite) return false;
  if (Session* existing = sessions_->by_id(invite->sid)) {
    joined = existing->sid;
    return true;
  }

  Peer& creator = peer_for(invite->creator_pk, invite->creator_name);
  creator.sign_pk = invite->creator_sign_pk;
  for (const auto& ep : invite->endpoints) add_endpoint(creator, ep);
  persist_contact(creator);
  if (invite->endpoints.empty()) discover_via_rendezvous(creator);

  Session session;
  session.sid = invite->sid;
  session.group = true;
  session.initiator = false;
  session.peer_pk = invite->creator_pk;
  session.peer_sign_pk = invite->creator_sign_pk;
  session.peer_name = sanitize_name(invite->creator_name);
  session.label = sanitize_name(invite->label);
  session.key_i2r = SecureBuffer(invite->group_key.data(), invite->group_key.size());
  session.key_r2i = SecureBuffer(invite->group_key.data(), invite->group_key.size());
  session.established = Clock::now();
  session.last_ratchet = session.established;
  session.members.push_back(GroupMember{invite->creator_pk, invite->creator_sign_pk,
                                        sanitize_name(invite->creator_name)});

  Session* added = sessions_->add(std::move(session));
  if (!added) {
    error = "could not join group";
    return false;
  }
  joined = added->sid;
  notify_session(*added);
  send_join_notice(*added);
  return true;
}

void Node::notify_session(Session& session) {
  if (!on_session) return;
  SessionView view;
  view.sid = session.sid;
  view.label = session.label;
  view.peer_pk = session.peer_pk;
  view.group = session.group;
  view.active = true;
  view.initiator = session.initiator;
  view.members = session.members;
  on_session(view);
}

std::string Node::own_invite() const {
  ContactInvite invite;
  invite.username = identity_.username;
  invite.pk = identity_.pk;
  invite.sign_pk = identity_.sign_pk;
  invite.endpoints = my_endpoints_;
  invite.rendezvous = rv_string_;
  return encode_contact_invite(invite);
}

bool Node::panic_wipe(std::string& error) {
  (void)error;
  stop();
  peers_.clear();
  incoming_requests_.clear();
  outgoing_requests_.clear();
  pending_wire_.clear();
  sessions_.reset();
  store_.reset();
  identity_.sk.wipe();
  identity_.sign_sk.wipe();
  LocalStore::wipe_files(config_.data_dir);
  IdentityManager::wipe(config_.data_dir);
  return true;
}

}  // namespace jn
