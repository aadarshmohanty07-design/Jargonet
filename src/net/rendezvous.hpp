#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "core/msgpack.hpp"
#include "net/endpoint.hpp"

namespace jn {

// The rendezvous service matches opaque 16-byte tags to UDP endpoints. It
// never receives usernames, public keys, message content or session ids.
constexpr std::size_t kRendezvousTagBytes = 16;
using RendezvousTag = std::array<std::uint8_t, kRendezvousTagBytes>;
constexpr char kRendezvousMagic[5] = {'J', 'N', 'R', 'V', '1'};
constexpr std::size_t kRendezvousHeaderBytes = 5;

RendezvousTag rendezvous_tag(const PublicKey& pk, int day_offset = 0);
std::array<RendezvousTag, 3> current_rendezvous_tags(const PublicKey& pk);

Bytes encode_rendezvous(const msg::Value& value);
std::optional<msg::Value> decode_rendezvous(const std::uint8_t* data, std::size_t size);
inline std::optional<msg::Value> decode_rendezvous(const Bytes& data) {
  return decode_rendezvous(data.data(), data.size());
}

Bytes make_register(const RendezvousTag& tag, std::uint32_t ttl_seconds, std::uint64_t request_id);
Bytes make_unregister(const RendezvousTag& tag, std::uint64_t request_id);
Bytes make_lookup(const RendezvousTag& tag, std::uint64_t request_id);
Bytes make_peers_response(std::uint64_t request_id, const std::vector<Endpoint>& endpoints);
Bytes make_ok_response(std::uint64_t request_id);
Bytes make_error_response(std::uint64_t request_id, const std::string& message);

std::vector<Endpoint> parse_peer_list(const msg::Value& value);

}  // namespace jn
