#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "core/crypto.hpp"
#include "net/endpoint.hpp"

namespace jn {

struct OnionHop {
  PublicKey pk{};
  Endpoint endpoint;
};

struct BuiltOnion {
  Endpoint first_hop;
  Bytes payload;
  std::size_t relay_count = 0;
};

struct PeeledLayer {
  enum class Kind { Invalid, Relay, Deliver };
  Kind kind = Kind::Invalid;
  Endpoint endpoint;
  Bytes inner;
};

// Layered, sealed-box onion:
//   outer = seal(relay_layer(next_hop, seal(inner))) ...
//   innermost = seal(deliver_layer(final_endpoint, packet))
// Each relay can open exactly one layer and learns only the next endpoint.
class OnionRouter {
 public:
  static std::optional<BuiltOnion> build(const std::vector<OnionHop>& hops,
                                         const Endpoint& final_endpoint,
                                         const Bytes& delivered_packet,
                                         std::string& error);

  static PeeledLayer peel(const PublicKey& self_pk, const SecureBuffer& self_sk,
                          const Bytes& payload);

  // Random distinct subset. Recipient and self are never used as relays.
  static std::vector<OnionHop> select_path(std::vector<OnionHop> candidates,
                                           const PublicKey& self,
                                           const PublicKey& recipient,
                                           std::size_t min_hops = 3,
                                           std::size_t max_hops = 5);

  // Conservative size an onion will add for a given number of hops.
  static std::size_t estimated_overhead(std::size_t hops);
};

}  // namespace jn
