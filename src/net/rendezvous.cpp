#include "net/rendezvous.hpp"

#include <chrono>
#include <cstring>

#include "core/crypto.hpp"

namespace jn {
namespace {

msg::Value endpoint_value(const Endpoint& endpoint) {
  return msg::Value::make_map({{"h", msg::Value(endpoint.host)},
                               {"p", msg::Value(static_cast<std::uint64_t>(endpoint.port))}});
}

std::optional<Endpoint> endpoint_from_value(const msg::Value& value) {
  try {
    std::string host = value.at("h").as_str();
    auto port = value.at("p").as_uint();
    if (port == 0 || port > 65535 || host.empty()) return std::nullopt;
    return Endpoint{host, static_cast<std::uint16_t>(port)};
  } catch (const msg::Error&) {
    return std::nullopt;
  }
}

}  // namespace

RendezvousTag rendezvous_tag(const PublicKey& pk, int day_offset) {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  std::int64_t days = std::chrono::duration_cast<std::chrono::hours>(now).count() / 24;
  days += day_offset;

  msg::Writer writer;
  writer.map(2);
  writer.str("d");
  writer.integer(days);
  writer.str("k");
  writer.bin(pk.data(), pk.size());
  Bytes input = writer.take();
  const char context[] = "jargonet/rendezvous-tag/v1";
  input.insert(input.begin(), context, context + std::strlen(context));

  Bytes digest = CryptoEngine::hash(input, kRendezvousTagBytes);
  RendezvousTag tag{};
  std::memcpy(tag.data(), digest.data(), tag.size());
  return tag;
}

std::array<RendezvousTag, 3> current_rendezvous_tags(const PublicKey& pk) {
  return {rendezvous_tag(pk, -1), rendezvous_tag(pk, 0), rendezvous_tag(pk, 1)};
}

Bytes encode_rendezvous(const msg::Value& value) {
  Bytes encoded = msg::encode(value);
  Bytes out;
  out.insert(out.end(), std::begin(kRendezvousMagic), std::end(kRendezvousMagic));
  out.insert(out.end(), encoded.begin(), encoded.end());
  return out;
}

std::optional<msg::Value> decode_rendezvous(const std::uint8_t* data, std::size_t size) {
  if (!data || size < kRendezvousHeaderBytes || size > 4096) return std::nullopt;
  if (std::memcmp(data, kRendezvousMagic, kRendezvousHeaderBytes) != 0) return std::nullopt;
  try {
    return msg::decode(data + kRendezvousHeaderBytes, size - kRendezvousHeaderBytes);
  } catch (const msg::Error&) {
    return std::nullopt;
  }
}

Bytes make_register(const RendezvousTag& tag, std::uint32_t ttl_seconds, std::uint64_t request_id) {
  return encode_rendezvous(msg::Value::make_map(
      {{"t", msg::Value("reg")},
       {"tag", msg::Value(Bytes(tag.begin(), tag.end()))},
       {"ttl", msg::Value(static_cast<std::uint64_t>(ttl_seconds))},
       {"id", msg::Value(request_id)}}));
}

Bytes make_unregister(const RendezvousTag& tag, std::uint64_t request_id) {
  return encode_rendezvous(msg::Value::make_map(
      {{"t", msg::Value("unreg")},
       {"tag", msg::Value(Bytes(tag.begin(), tag.end()))},
       {"id", msg::Value(request_id)}}));
}

Bytes make_lookup(const RendezvousTag& tag, std::uint64_t request_id) {
  return encode_rendezvous(
      msg::Value::make_map({{"t", msg::Value("lookup")},
                            {"tag", msg::Value(Bytes(tag.begin(), tag.end()))},
                            {"id", msg::Value(request_id)}}));
}

Bytes make_peers_response(std::uint64_t request_id, const std::vector<Endpoint>& endpoints) {
  msg::Value list;
  list.type = msg::Value::Type::Array;
  for (const auto& ep : endpoints) list.array.push_back(endpoint_value(ep));
  return encode_rendezvous(msg::Value::make_map(
      {{"t", msg::Value("peers")}, {"id", msg::Value(request_id)}, {"eps", std::move(list)}}));
}

Bytes make_ok_response(std::uint64_t request_id) {
  return encode_rendezvous(
      msg::Value::make_map({{"t", msg::Value("ok")}, {"id", msg::Value(request_id)}}));
}

Bytes make_error_response(std::uint64_t request_id, const std::string& message) {
  return encode_rendezvous(msg::Value::make_map(
      {{"t", msg::Value("err")}, {"id", msg::Value(request_id)}, {"msg", msg::Value(message)}}));
}

std::vector<Endpoint> parse_peer_list(const msg::Value& value) {
  std::vector<Endpoint> out;
  const msg::Value* eps = value.find("eps");
  if (!eps || eps->type != msg::Value::Type::Array) return out;
  for (const auto& item : eps->array) {
    auto ep = endpoint_from_value(item);
    if (ep) out.push_back(*ep);
    if (out.size() >= 16) break;
  }
  return out;
}

}  // namespace jn
