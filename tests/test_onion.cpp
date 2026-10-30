#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "core/packet.hpp"
#include "routing/onion.hpp"
#include "test_util.hpp"

using namespace jn;

void run() {
  auto r1 = CryptoEngine::generate_box_keypair();
  auto r2 = CryptoEngine::generate_box_keypair();
  auto r3 = CryptoEngine::generate_box_keypair();
  auto outsider = CryptoEngine::generate_box_keypair();

  std::vector<OnionHop> path = {
      {r1.pk, {"127.0.0.1", 41001}},
      {r2.pk, {"127.0.0.1", 41002}},
      {r3.pk, {"127.0.0.1", 41003}},
  };
  Endpoint recipient{"127.0.0.1", 41099};

  Bytes delivered = Bytes(400, 0x7E);
  std::string error;
  auto onion = OnionRouter::build(path, recipient, delivered, error);
  CHECK(onion.has_value());
  if (!onion) {
    std::cerr << "build error: " << error << "\n";
    return;
  }
  CHECK(onion->first_hop == path[0].endpoint);
  CHECK(onion->relay_count == 3);
  CHECK(onion->payload.size() <= kMaxPayloadBytes);
  CHECK(onion->payload != delivered);
  const std::string marker(16, static_cast<char>(0x7E));
  std::string onion_text(reinterpret_cast<const char*>(onion->payload.data()),
                         onion->payload.size());
  CHECK(onion_text.find(marker) == std::string::npos);

  // Only the intended relay can peel the outer layer.
  PeeledLayer outsider_peel = OnionRouter::peel(outsider.pk, outsider.sk, onion->payload);
  CHECK(outsider_peel.kind == PeeledLayer::Kind::Invalid);

  PeeledLayer first = OnionRouter::peel(r1.pk, r1.sk, onion->payload);
  CHECK(first.kind == PeeledLayer::Kind::Relay);
  CHECK(first.endpoint == path[1].endpoint);
  CHECK(!first.inner.empty());

  // Relay 1 cannot read the layer addressed to relay 2.
  PeeledLayer wrong_again = OnionRouter::peel(r1.pk, r1.sk, first.inner);
  CHECK(wrong_again.kind == PeeledLayer::Kind::Invalid);
  PeeledLayer outsider_inner = OnionRouter::peel(outsider.pk, outsider.sk, first.inner);
  CHECK(outsider_inner.kind == PeeledLayer::Kind::Invalid);

  PeeledLayer second = OnionRouter::peel(r2.pk, r2.sk, first.inner);
  CHECK(second.kind == PeeledLayer::Kind::Relay);
  CHECK(second.endpoint == path[2].endpoint);

  PeeledLayer third = OnionRouter::peel(r3.pk, r3.sk, second.inner);
  CHECK(third.kind == PeeledLayer::Kind::Deliver);
  CHECK(third.endpoint == recipient);
  CHECK(third.inner == delivered);

  // Tampering is rejected by the sealed box.
  Bytes tampered = onion->payload;
  tampered[tampered.size() / 2] ^= 0x01;
  CHECK(OnionRouter::peel(r1.pk, r1.sk, tampered).kind == PeeledLayer::Kind::Invalid);

  // Five-hop onions fit in one datagram for a chat-sized payload.
  auto r4 = CryptoEngine::generate_box_keypair();
  auto r5 = CryptoEngine::generate_box_keypair();
  std::vector<OnionHop> five = {
      {r1.pk, {"127.0.0.1", 1}}, {r2.pk, {"127.0.0.1", 2}},
      {r3.pk, {"127.0.0.1", 3}}, {r4.pk, {"127.0.0.1", 4}},
      {r5.pk, {"127.0.0.1", 5}},
  };
  Packet inner;
  inner.type = PacketType::Direct;
  inner.msg_id = 1;
  inner.payload = Bytes(650, 0x11);
  auto big = OnionRouter::build(five, recipient, serialize_packet(inner), error);
  CHECK(big.has_value());
  if (big) CHECK(big->payload.size() <= kMaxPayloadBytes);

  // Oversized inner packets are refused rather than fragmented.
  Packet huge;
  huge.type = PacketType::Direct;
  huge.msg_id = 2;
  huge.payload = Bytes(kMaxPayloadBytes, 0x22);
  CHECK(!OnionRouter::build(five, recipient, serialize_packet(huge), error));

  // Duplicate hops are rejected.
  std::vector<OnionHop> duplicate = {path[0], path[0]};
  CHECK(!OnionRouter::build(duplicate, recipient, delivered, error));

  // Path selection constraints.
  PublicKey self{};
  self[0] = 9;
  std::vector<OnionHop> candidates;
  for (int i = 0; i < 8; ++i) {
    auto kp = CryptoEngine::generate_box_keypair();
    candidates.push_back({kp.pk, {"127.0.0.1", static_cast<std::uint16_t>(50000 + i)}});
  }
  candidates.push_back({self, {"127.0.0.1", 50010}});
  candidates.push_back({path[0].pk, {"127.0.0.1", 50011}});
  auto selected = OnionRouter::select_path(candidates, self, r1.pk, 3, 5);
  CHECK(selected.size() >= 3 && selected.size() <= 5);
  std::set<std::string> pks;
  for (const auto& hop : selected) {
    CHECK(hop.pk != self);
    CHECK(hop.pk != r1.pk);
    pks.insert(std::string(reinterpret_cast<const char*>(hop.pk.data()), hop.pk.size()));
  }
  CHECK(pks.size() == selected.size());

  auto none = OnionRouter::select_path({{self, {"127.0.0.1", 1}},
                                        {r1.pk, {"127.0.0.1", 2}}},
                                       self, r1.pk, 3, 5);
  CHECK(none.empty());
}

TEST_MAIN()
