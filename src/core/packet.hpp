#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include "core/bytes.hpp"

namespace jn {

// Wire packet layout (all integers big endian):
//   magic "JGN1" | version u8 | type u8 | flags u8 | ttl u8 |
//   session id 16 | message id u64 | nonce 24 | payload length u16 | payload
constexpr std::uint8_t kProtocolVersion = 1;
constexpr std::size_t kPacketHeaderBytes = 4 + 1 + 1 + 1 + 1 + 16 + 8 + 24 + 2;
constexpr std::size_t kMaxDatagramBytes = 1200;
constexpr std::size_t kMaxPayloadBytes = kMaxDatagramBytes - kPacketHeaderBytes;
constexpr std::uint8_t kMaxInitialTtl = 8;

enum class PacketType : std::uint8_t {
  Discovery = 1,
  ChatRequest = 2,
  ChatAccept = 3,
  OnionData = 4,
  Ack = 5,
  RelayAnnounce = 6,
  Direct = 7,
  Ping = 8,
  Pong = 9,
  Ratchet = 10,
  Hello = 11,
  Punch = 12,
};

enum PacketFlags : std::uint8_t {
  kFlagNone = 0,
  kFlagOnionDelivered = 1 << 0,
};

class PacketError : public std::runtime_error {
 public:
  explicit PacketError(const std::string& what) : std::runtime_error(what) {}
};

struct Packet {
  PacketType type = PacketType::Ping;
  std::uint8_t flags = kFlagNone;
  std::uint8_t ttl = 0;
  SessionId session{};
  std::uint64_t msg_id = 0;
  Nonce nonce{};
  Bytes payload;
};

bool is_known_packet_type(std::uint8_t raw);
const char* packet_type_name(PacketType type);

Bytes serialize_packet(const Packet& packet);
Packet parse_packet(const std::uint8_t* data, std::size_t size);
Packet parse_packet(const Bytes& data);

std::uint64_t new_message_id();
SessionId random_session_id();

}  // namespace jn
