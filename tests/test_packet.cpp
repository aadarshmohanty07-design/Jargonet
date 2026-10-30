#include "core/packet.hpp"
#include "test_util.hpp"

using namespace jn;

void run() {
  Packet packet;
  packet.type = PacketType::Direct;
  packet.flags = kFlagOnionDelivered;
  packet.ttl = 3;
  packet.session = random_session_id();
  packet.msg_id = new_message_id();
  packet.nonce = CryptoEngine::random_nonce();
  packet.payload = Bytes(200, 0x5A);

  Bytes wire = serialize_packet(packet);
  CHECK(wire.size() == kPacketHeaderBytes + packet.payload.size());
  CHECK(kPacketHeaderBytes == 58);
  CHECK(wire[0] == 'J' && wire[1] == 'G' && wire[2] == 'N' && wire[3] == '1');
  CHECK(wire[4] == kProtocolVersion);

  Packet parsed = parse_packet(wire);
  CHECK(parsed.type == PacketType::Direct);
  CHECK(parsed.flags == kFlagOnionDelivered);
  CHECK(parsed.ttl == 3);
  CHECK(parsed.session == packet.session);
  CHECK(parsed.msg_id == packet.msg_id);
  CHECK(parsed.nonce == packet.nonce);
  CHECK(parsed.payload == packet.payload);

  // All packet types round-trip.
  for (std::uint8_t raw = 1; raw <= static_cast<std::uint8_t>(PacketType::Punch); ++raw) {
    CHECK(is_known_packet_type(raw));
    Packet p;
    p.type = static_cast<PacketType>(raw);
    p.msg_id = new_message_id();
    p.payload = Bytes{1, 2, 3};
    Packet back = parse_packet(serialize_packet(p));
    CHECK(back.type == p.type);
  }

  // Invalid inputs.
  Bytes bad_magic = wire;
  bad_magic[0] = 'X';
  CHECK_THROWS(parse_packet(bad_magic));

  Bytes bad_version = wire;
  bad_version[4] = 9;
  CHECK_THROWS(parse_packet(bad_version));

  Bytes unknown_type = wire;
  unknown_type[5] = 99;
  CHECK_THROWS(parse_packet(unknown_type));

  Bytes bad_ttl = wire;
  bad_ttl[7] = kMaxInitialTtl + 1;
  CHECK_THROWS(parse_packet(bad_ttl));

  Bytes short_packet(wire.begin(), wire.begin() + 20);
  CHECK_THROWS(parse_packet(short_packet));

  Bytes truncated(wire.begin(), wire.end() - 1);
  CHECK_THROWS(parse_packet(truncated));

  Packet too_large;
  too_large.type = PacketType::Direct;
  too_large.msg_id = 1;
  too_large.payload = Bytes(kMaxPayloadBytes + 1, 0);
  CHECK_THROWS(serialize_packet(too_large));

  // ACKs must reference a message.
  Packet empty_ack;
  empty_ack.type = PacketType::Ack;
  empty_ack.msg_id = 0;
  CHECK_THROWS(parse_packet(serialize_packet(empty_ack)));

  // Oversized UDP input is rejected before parsing.
  Bytes giant(kMaxDatagramBytes + 1, 0);
  CHECK_THROWS(parse_packet(giant));
}

TEST_MAIN()
