#include "routing/onion.hpp"

#include <algorithm>
#include <unordered_set>

#include "core/msgpack.hpp"
#include "core/packet.hpp"

namespace jn {
namespace {

Bytes wrap_layer(char kind, const Endpoint& endpoint, const Bytes& inner) {
  msg::Writer writer;
  writer.map(4);
  writer.str("t");
  writer.str(kind == 'd' ? "d" : "r");
  writer.str("ip");
  writer.str(endpoint.host);
  writer.str("pt");
  writer.uint(endpoint.port);
  writer.str("d");
  writer.bin(inner);
  return writer.take();
}

Endpoint endpoint_from_layer(const msg::Value& layer, bool& ok) {
  ok = false;
  try {
    const std::string ip = layer.at("ip").as_str();
    const std::uint64_t port = layer.at("pt").as_uint();
    if (ip.empty() || port == 0 || port > 65535) return {};
    const auto parsed = Endpoint::parse(ip.find(':') == std::string::npos
                                            ? ip + ":" + std::to_string(port)
                                            : "[" + ip + "]:" + std::to_string(port));
    if (!parsed) return {};
    ok = true;
    return *parsed;
  } catch (const msg::Error&) {
    return {};
  }
}

}  // namespace

std::size_t OnionRouter::estimated_overhead(std::size_t hops) {
  // Delivery layer metadata + sealed-box overhead, plus one relay layer per
  // additional hop. Deliberately generous.
  return 180 + hops * 90;
}

std::optional<BuiltOnion> OnionRouter::build(const std::vector<OnionHop>& hops,
                                             const Endpoint& final_endpoint,
                                             const Bytes& delivered_packet,
                                             std::string& error) {
  if (hops.empty()) {
    error = "onion path is empty";
    return std::nullopt;
  }
  if (!final_endpoint.valid()) {
    error = "invalid final endpoint";
    return std::nullopt;
  }
  if (delivered_packet.empty()) {
    error = "empty delivered packet";
    return std::nullopt;
  }

  std::unordered_set<std::string> seen;
  for (const auto& hop : hops) {
    if (!CryptoEngine::valid_public_key(hop.pk)) {
      error = "relay has an invalid public key";
      return std::nullopt;
    }
    if (!hop.endpoint.valid()) {
      error = "relay has an invalid endpoint";
      return std::nullopt;
    }
    std::string key(reinterpret_cast<const char*>(hop.pk.data()), hop.pk.size());
    if (!seen.insert(key).second) {
      error = "duplicate relay in onion path";
      return std::nullopt;
    }
  }

  try {
    Bytes layer = wrap_layer('d', final_endpoint, delivered_packet);
    for (std::size_t i = hops.size(); i-- > 0;) {
      Bytes sealed = CryptoEngine::box_seal(hops[i].pk, layer.data(), layer.size());
      if (i == 0) {
        if (sealed.size() > kMaxPayloadBytes) {
          error = "onion exceeds UDP packet budget";
          return std::nullopt;
        }
        BuiltOnion onion;
        onion.first_hop = hops[0].endpoint;
        onion.payload = std::move(sealed);
        onion.relay_count = hops.size();
        return onion;
      }
      layer = wrap_layer('r', hops[i].endpoint, sealed);
      if (layer.size() > kMaxPayloadBytes) {
        error = "onion exceeds UDP packet budget";
        return std::nullopt;
      }
    }
  } catch (const CryptoError& e) {
    error = e.what();
    return std::nullopt;
  }
  error = "failed to build onion";
  return std::nullopt;
}

PeeledLayer OnionRouter::peel(const PublicKey& self_pk, const SecureBuffer& self_sk,
                              const Bytes& payload) {
  PeeledLayer result;
  Bytes plain;
  try {
    plain = CryptoEngine::box_seal_open(self_pk, self_sk, payload.data(), payload.size());
  } catch (const CryptoError&) {
    return result;
  }

  try {
    msg::Value layer = msg::decode(plain);
    const std::string type = layer.at("t").as_str();
    bool ok = false;
    Endpoint endpoint = endpoint_from_layer(layer, ok);
    if (!ok) return result;
    const Bytes& inner = layer.at("d").as_bin();
    if (inner.empty()) return result;
    result.endpoint = endpoint;
    result.inner = inner;
    if (type == "d") {
      result.kind = PeeledLayer::Kind::Deliver;
    } else if (type == "r") {
      result.kind = PeeledLayer::Kind::Relay;
    }
  } catch (const msg::Error&) {
    result.kind = PeeledLayer::Kind::Invalid;
  }
  return result;
}

std::vector<OnionHop> OnionRouter::select_path(std::vector<OnionHop> candidates,
                                               const PublicKey& self,
                                               const PublicKey& recipient,
                                               std::size_t min_hops,
                                               std::size_t max_hops) {
  candidates.erase(
      std::remove_if(candidates.begin(), candidates.end(),
                     [&](const OnionHop& hop) {
                       return hop.pk == self || hop.pk == recipient ||
                              !hop.endpoint.valid() || !CryptoEngine::valid_public_key(hop.pk);
                     }),
      candidates.end());

  std::vector<OnionHop> unique;
  std::unordered_set<std::string> seen;
  for (const auto& hop : candidates) {
    std::string key(reinterpret_cast<const char*>(hop.pk.data()), hop.pk.size());
    if (seen.insert(key).second) unique.push_back(hop);
  }

  // Fisher-Yates with libsodium randomness.
  for (std::size_t i = unique.size(); i > 1; --i) {
    const std::uint32_t j = CryptoEngine::random_u32(static_cast<std::uint32_t>(i));
    std::swap(unique[i - 1], unique[j]);
  }

  if (unique.empty()) return {};
  min_hops = std::max<std::size_t>(1, min_hops);
  max_hops = std::max(min_hops, max_hops);
  const std::size_t limit = std::min(max_hops, unique.size());
  std::size_t count = min_hops;
  if (limit > min_hops) {
    count = min_hops + CryptoEngine::random_u32(static_cast<std::uint32_t>(limit - min_hops + 1));
  }
  count = std::min(count, unique.size());
  unique.resize(count);
  return unique;
}

}  // namespace jn
