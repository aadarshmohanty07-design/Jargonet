#include "core/packet.hpp"

#include <cstring>

#include "core/crypto.hpp"

namespace jn {
namespace {

constexpr std::uint8_t kMagic[4] = {'J', 'G', 'N', '1'};

void put_u16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

std::uint16_t get_u16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

void put_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

}  // namespace

bool is_known_packet_type(std::uint8_t raw) {
  return raw >= static_cast<std::uint8_t>(PacketType::Discovery) &&
         raw <= static_cast<std::uint8_t>(PacketType::Punch);
}

const char* packet_type_name(PacketType type) {
  switch (type) {
    case PacketType::Discovery: return "DISCOVERY";
    case PacketType::ChatRequest: return "CHAT_REQUEST";
    case PacketType::ChatAccept: return "CHAT_ACCEPT";
    case PacketType::OnionData: return "ONION_DATA";
    case PacketType::Ack: return "ACK";
    case PacketType::RelayAnnounce: return "RELAY_ANNOUNCE";
    case PacketType::Direct: return "DIRECT";
    case PacketType::Ping: return "PING";
    case PacketType::Pong: return "PONG";
    case PacketType::Ratchet: return "RATCHET";
    case PacketType::Hello: return "HELLO";
    case PacketType::Punch: return "PUNCH";
  }
  return "UNKNOWN";
}

std::uint64_t new_message_id() {
  std::uint64_t id = 0;
  while (id == 0) {
    auto bytes = CryptoEngine::random_bytes(8);
    std::memcpy(&id, bytes.data(), 8);
  }
  return id;
}

SessionId random_session_id() {
  SessionId id{};
  auto bytes = CryptoEngine::random_bytes(id.size());
  std::memcpy(id.data(), bytes.data(), id.size());
  return id;
}

Bytes serialize_packet(const Packet& packet) {
  if (!is_known_packet_type(static_cast<std::uint8_t>(packet.type))) {
    throw PacketError("unknown packet type");
  }
  if (packet.payload.size() > kMaxPayloadBytes) {
    throw PacketError("packet payload exceeds UDP budget");
  }
  if (packet.ttl > kMaxInitialTtl) throw PacketError("ttl out of range");

  Bytes out;
  out.reserve(kPacketHeaderBytes + packet.payload.size());
  out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
  out.push_back(kProtocolVersion);
  out.push_back(static_cast<std::uint8_t>(packet.type));
  out.push_back(packet.flags);
  out.push_back(packet.ttl);
  out.insert(out.end(), packet.session.begin(), packet.session.end());
  put_u64(out, packet.msg_id);
  out.insert(out.end(), packet.nonce.begin(), packet.nonce.end());
  put_u16(out, static_cast<std::uint16_t>(packet.payload.size()));
  out.insert(out.end(), packet.payload.begin(), packet.payload.end());
  return out;
}

Packet parse_packet(const std::uint8_t* data, std::size_t size) {
  if (!data || size < kPacketHeaderBytes) throw PacketError("truncated packet header");
  if (size > kMaxDatagramBytes) throw PacketError("packet exceeds UDP budget");
  if (std::memcmp(data, kMagic, sizeof(kMagic)) != 0) throw PacketError("bad packet magic");
  if (data[4] != kProtocolVersion) throw PacketError("unsupported protocol version");
  if (!is_known_packet_type(data[5])) throw PacketError("unknown packet type");
  if (data[7] > kMaxInitialTtl) throw PacketError("ttl out of range");

  Packet packet;
  packet.type = static_cast<PacketType>(data[5]);
  packet.flags = data[6];
  packet.ttl = data[7];
  std::memcpy(packet.session.data(), data + 8, packet.session.size());
  packet.msg_id = get_u64(data + 24);
  std::memcpy(packet.nonce.data(), data + 32, packet.nonce.size());
  const std::uint16_t payload_len = get_u16(data + 56);
  const std::size_t expected = kPacketHeaderBytes + payload_len;
  if (expected != size) throw PacketError("packet length mismatch");
  if (payload_len > kMaxPayloadBytes) throw PacketError("packet payload too large");
  packet.payload.assign(data + kPacketHeaderBytes, data + expected);
  if (packet.type == PacketType::Ack && packet.msg_id == 0) {
    throw PacketError("ack without message id");
  }
  return packet;
}

Packet parse_packet(const Bytes& data) { return parse_packet(data.data(), data.size()); }

}  // namespace jn
