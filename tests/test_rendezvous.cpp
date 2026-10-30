#include <chrono>
#include <cstring>

#include "core/crypto.hpp"
#include "net/rendezvous.hpp"
#include "net/rendezvous_server.hpp"
#include "net/stun.hpp"
#include "net/udp_socket.hpp"
#include "test_util.hpp"

using namespace jn;

namespace {

std::optional<Bytes> recv_with_server(RendezvousServer& server, UdpSocket& socket, int ms) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (std::chrono::steady_clock::now() < deadline) {
    server.run_once(5);
    auto datagram = socket.recv_from();
    if (datagram) return datagram->data;
  }
  return std::nullopt;
}

}  // namespace

void run() {
  // Tag derivation is stable per peer/day and unlinkable across days.
  auto identity = CryptoEngine::generate_box_keypair();
  auto other = CryptoEngine::generate_box_keypair();
  RendezvousTag today = rendezvous_tag(identity.pk, 0);
  CHECK(today == rendezvous_tag(identity.pk, 0));
  CHECK(today != rendezvous_tag(identity.pk, 1));
  CHECK(today != rendezvous_tag(other.pk, 0));
  auto tags = current_rendezvous_tags(identity.pk);
  CHECK(tags[1] == today);
  CHECK(tags[0] == rendezvous_tag(identity.pk, -1));

  // Rendezvous registration and lookup.
  RendezvousServer::Config config;
  config.bind = Endpoint{"127.0.0.1", 0};
  RendezvousServer server(config);
  std::string error;
  CHECK(server.start(error));
  const Endpoint server_endpoint{"127.0.0.1", server.port()};
  CHECK(server.port() != 0);

  UdpSocket alice;
  UdpSocket bob;
  CHECK(alice.open(0, error));
  CHECK(bob.open(0, error));

  const std::uint64_t register_id = 111;
  CHECK(alice.send_to(server_endpoint, make_register(tags[1], 60, register_id)));
  auto reply = recv_with_server(server, alice, 1000);
  CHECK(reply.has_value());
  if (reply) {
    auto value = decode_rendezvous(*reply);
    CHECK(value.has_value());
    if (value) {
      CHECK(value->at("t").as_str() == "ok");
      CHECK(value->at("id").as_uint() == register_id);
    }
  }
  CHECK(server.tag_count() == 1);
  CHECK(server.registered_endpoint_count() == 1);

  // Bob registers under his own tag then looks up Alice's tag.
  CHECK(bob.send_to(server_endpoint, make_register(rendezvous_tag(other.pk), 60, 222)));
  auto bob_ok = recv_with_server(server, bob, 1000);
  CHECK(bob_ok.has_value());

  const std::uint64_t lookup_id = 333;
  CHECK(bob.send_to(server_endpoint, make_lookup(tags[1], lookup_id)));
  auto peers_reply = recv_with_server(server, bob, 1000);
  CHECK(peers_reply.has_value());
  if (peers_reply) {
    auto value = decode_rendezvous(*peers_reply);
    CHECK(value.has_value());
    if (value) {
      CHECK(value->at("t").as_str() == "peers");
      CHECK(value->at("id").as_uint() == lookup_id);
      auto endpoints = parse_peer_list(*value);
      CHECK(endpoints.size() == 1);
      if (!endpoints.empty()) {
        CHECK(endpoints[0].host == "127.0.0.1");
        CHECK(endpoints[0].port == alice.local_port());
      }
    }
  }

  // Malformed and invalid-length tags are rejected without crashing the server.
  CHECK(alice.send_to(server_endpoint, encode_rendezvous(msg::Value::make_map(
                                     {{"t", msg::Value("lookup")},
                                      {"tag", msg::Value(Bytes(3, 1))},
                                      {"id", msg::Value(9)}}))));
  auto bad_reply = recv_with_server(server, alice, 1000);
  CHECK(bad_reply.has_value());
  if (bad_reply) {
    auto value = decode_rendezvous(*bad_reply);
    CHECK(value.has_value());
    if (value) CHECK(value->at("t").as_str() == "err");
  }

  // Unregister removes the endpoint.
  CHECK(alice.send_to(server_endpoint, make_unregister(tags[1], 444)));
  auto unreg_ok = recv_with_server(server, alice, 1000);
  CHECK(unreg_ok.has_value());
  CHECK(server.tag_count() == 1);  // bob's tag remains

  alice.close();
  bob.close();
  server.stop();

  // STUN response parsing.
  StunTransactionId txn{};
  for (std::size_t i = 0; i < txn.size(); ++i) txn[i] = static_cast<std::uint8_t>(i + 1);
  const std::uint16_t mapped_port = 54321;
  const std::uint32_t mapped_ip = 0x7F000001;  // 127.0.0.1
  Bytes response(20);
  response[0] = 0x01;
  response[1] = 0x01;  // binding success
  response[2] = 0;
  response[3] = 12;    // attribute length
  response[4] = 0x21;
  response[5] = 0x12;
  response[6] = 0xA4;
  response[7] = 0x42;
  std::memcpy(response.data() + 8, txn.data(), txn.size());
  response.push_back(0x00);
  response.push_back(0x20);  // XOR-MAPPED-ADDRESS
  response.push_back(0x00);
  response.push_back(0x08);
  response.push_back(0x00);
  response.push_back(0x01);  // IPv4
  const std::uint16_t xor_port = mapped_port ^ 0x2112;
  response.push_back(static_cast<std::uint8_t>(xor_port >> 8));
  response.push_back(static_cast<std::uint8_t>(xor_port));
  const std::uint32_t xor_ip = mapped_ip ^ 0x2112A442;
  response.push_back(static_cast<std::uint8_t>(xor_ip >> 24));
  response.push_back(static_cast<std::uint8_t>(xor_ip >> 16));
  response.push_back(static_cast<std::uint8_t>(xor_ip >> 8));
  response.push_back(static_cast<std::uint8_t>(xor_ip));

  auto mapped = parse_stun_binding_response(response.data(), response.size(), &txn);
  CHECK(mapped.has_value());
  if (mapped) {
    CHECK(mapped->host == "127.0.0.1");
    CHECK(mapped->port == mapped_port);
  }
  StunTransactionId wrong_txn = txn;
  wrong_txn[0] ^= 1;
  CHECK(!parse_stun_binding_response(response.data(), response.size(), &wrong_txn).has_value());
  Bytes truncated(response.begin(), response.end() - 2);
  CHECK(!parse_stun_binding_response(truncated.data(), truncated.size(), &txn).has_value());
  Bytes tampered = response;
  tampered[2] = 0xFF;  // length beyond the packet
  CHECK(!parse_stun_binding_response(tampered.data(), tampered.size(), &txn).has_value());

  auto request = build_stun_binding_request(txn);
  CHECK(request.size() == 20);
  CHECK(request[4] == 0x21 && request[5] == 0x12 && request[6] == 0xA4 && request[7] == 0x42);
}

TEST_MAIN()
