#include "session/dispatcher.hpp"

#include "routing/onion.hpp"

namespace jn {

Packet MessageDispatcher::build_direct(const Session& session, ChatKind kind,
                                      const std::string& text, std::uint64_t msg_id,
                                      std::uint64_t seq, std::uint8_t flags) const {
  ChatPayload content;
  content.sid = session.sid;
  content.from_pk = identity_.pk;
  content.from_name = identity_.username;
  content.sign_pk = identity_.sign_pk;
  content.text = text;
  content.seq = seq;
  content.epoch = session.epoch;
  content.kind = kind;
  content.msg_id = msg_id;

  Packet packet;
  packet.type = PacketType::Direct;
  packet.flags = flags;
  packet.session = session.sid;
  packet.msg_id = msg_id;
  packet.payload = encrypt_chat_payload(identity_, session, content);
  return packet;
}

std::optional<BuiltOnion> MessageDispatcher::build_onion(
    const Session& session, ChatKind kind, const std::string& text, std::uint64_t msg_id,
    std::uint64_t seq, const Endpoint& recipient, const std::vector<OnionHop>& path,
    std::string& error) const {
  Packet direct = build_direct(session, kind, text, msg_id, seq, kFlagOnionDelivered);
  Bytes packet_bytes = serialize_packet(direct);
  return OnionRouter::build(path, recipient, packet_bytes, error);
}

std::optional<ChatPayload> MessageDispatcher::open(const Session& session, const Packet& packet,
                                                   std::string& error) const {
  if (packet.type != PacketType::Direct) {
    error = "not a direct packet";
    return std::nullopt;
  }
  return decrypt_chat_payload(identity_, session, packet.payload, packet.msg_id, error);
}

}  // namespace jn
