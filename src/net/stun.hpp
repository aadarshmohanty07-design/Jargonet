#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "core/bytes.hpp"
#include "net/endpoint.hpp"

namespace jn {

using StunTransactionId = std::array<std::uint8_t, 12>;

// Parses an RFC 5389 Binding Success Response. If expected is provided the
// transaction id must match.
std::optional<Endpoint> parse_stun_binding_response(const std::uint8_t* data, std::size_t size,
                                                    const StunTransactionId* expected = nullptr);

// Best-effort STUN discovery on an existing UDP socket. Consumes datagrams on
// that socket while waiting, so call it before the event loop starts.
std::optional<Endpoint> stun_discover(class UdpSocket& socket, const Endpoint& server,
                                      int timeout_ms);

Bytes build_stun_binding_request(const StunTransactionId& transaction);

}  // namespace jn
