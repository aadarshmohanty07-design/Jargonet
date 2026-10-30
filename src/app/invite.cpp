#include "app/invite.hpp"

#include <algorithm>
#include <cstring>

#include "core/encoding.hpp"
#include "core/msgpack.hpp"

namespace jn {
namespace {

constexpr const char* kContactPrefix = "jn1:";
constexpr const char* kGroupPrefix = "jng1:";

msg::Value endpoints_to_value(const std::vector<Endpoint>& endpoints) {
  msg::Value array;
  array.type = msg::Value::Type::Array;
  for (const auto& ep : endpoints) {
    if (!ep.valid()) continue;
    array.array.push_back(msg::Value(ep.to_string()));
    if (array.array.size() >= 8) break;
  }
  return array;
}

std::vector<Endpoint> endpoints_from_value(const msg::Value* value) {
  std::vector<Endpoint> out;
  if (!value || value->type != msg::Value::Type::Array) return out;
  for (const auto& item : value->array) {
    if (item.type != msg::Value::Type::Str) continue;
    auto ep = Endpoint::parse(item.str);
    if (ep) out.push_back(*ep);
    if (out.size() >= 8) break;
  }
  return out;
}

std::string decode_body(std::string_view code, const char* prefix, std::string& error) {
  std::string trimmed = trim(code);
  if (trimmed.rfind(prefix, 0) != 0) {
    error = "not a Jargonet invite code";
    return {};
  }
  auto raw = base64url_decode(std::string_view(trimmed).substr(std::strlen(prefix)));
  if (!raw) {
    error = "invalid invite encoding";
    return {};
  }
  return std::string(reinterpret_cast<const char*>(raw->data()), raw->size());
}

PublicKey public_key_from(const msg::Value& value) {
  const Bytes& bytes = value.as_bin();
  if (bytes.size() != kPublicKeyBytes) throw msg::Error("invalid public key");
  PublicKey pk{};
  std::copy(bytes.begin(), bytes.end(), pk.begin());
  return pk;
}

SignPublicKey sign_key_from(const msg::Value& value) {
  const Bytes& bytes = value.as_bin();
  if (bytes.size() != kSignPublicKeyBytes) throw msg::Error("invalid signing key");
  SignPublicKey pk{};
  std::copy(bytes.begin(), bytes.end(), pk.begin());
  return pk;
}

}  // namespace

std::string encode_contact_invite(const ContactInvite& invite) {
  msg::Writer writer;
  writer.map(7);
  writer.str("v");
  writer.uint(1);
  writer.str("t");
  writer.str("c");
  writer.str("n");
  writer.str(invite.username);
  writer.str("pk");
  writer.bin(invite.pk.data(), invite.pk.size());
  writer.str("spk");
  writer.bin(invite.sign_pk.data(), invite.sign_pk.size());
  writer.str("ep");
  msg::Value eps = endpoints_to_value(invite.endpoints);
  Bytes ep_bytes = msg::encode(eps);
  writer.bin(ep_bytes);
  writer.str("rv");
  writer.str(invite.rendezvous);
  Bytes body = writer.take();
  return std::string(kContactPrefix) + base64url_encode(body);
}

std::optional<ContactInvite> decode_contact_invite(std::string_view code, std::string& error) {
  std::string body = decode_body(code, kContactPrefix, error);
  if (body.empty()) return std::nullopt;
  try {
    auto raw = base64url_decode(code.substr(std::strlen(kContactPrefix)));
    (void)raw;
    msg::Value root = msg::decode(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
    if (root.at("v").as_uint() != 1 || root.at("t").as_str() != "c") {
      error = "unsupported invite version";
      return std::nullopt;
    }
    ContactInvite invite;
    invite.username = root.at("n").as_str();
    invite.pk = public_key_from(root.at("pk"));
    invite.sign_pk = sign_key_from(root.at("spk"));
    const Bytes& ep_bytes = root.at("ep").as_bin();
    msg::Value eps = msg::decode(ep_bytes);
    invite.endpoints = endpoints_from_value(&eps);
    invite.rendezvous = root.at("rv").as_str();
    if (is_zero(invite.pk) || is_zero(invite.sign_pk)) {
      error = "invite contains a degenerate key";
      return std::nullopt;
    }
    return invite;
  } catch (const msg::Error& e) {
    error = std::string("malformed contact invite: ") + e.what();
    return std::nullopt;
  }
}

std::string encode_group_invite(const GroupInvite& invite) {
  msg::Writer writer;
  writer.map(10);
  writer.str("v");
  writer.uint(1);
  writer.str("t");
  writer.str("g");
  writer.str("sid");
  writer.bin(invite.sid.data(), invite.sid.size());
  writer.str("key");
  writer.bin(invite.group_key);
  writer.str("n");
  writer.str(invite.label);
  writer.str("pk");
  writer.bin(invite.creator_pk.data(), invite.creator_pk.size());
  writer.str("spk");
  writer.bin(invite.creator_sign_pk.data(), invite.creator_sign_pk.size());
  writer.str("cn");
  writer.str(invite.creator_name);
  writer.str("ep");
  writer.bin(msg::encode(endpoints_to_value(invite.endpoints)));
  writer.str("rv");
  writer.str(invite.rendezvous);
  Bytes body = writer.take();
  return std::string(kGroupPrefix) + base64url_encode(body);
}

std::optional<GroupInvite> decode_group_invite(std::string_view code, std::string& error) {
  std::string body = decode_body(code, kGroupPrefix, error);
  if (body.empty()) return std::nullopt;
  try {
    msg::Value root = msg::decode(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
    if (root.at("v").as_uint() != 1 || root.at("t").as_str() != "g") {
      error = "unsupported group invite version";
      return std::nullopt;
    }
    GroupInvite invite;
    invite.sid = root.at("sid").as_session_id();
    invite.group_key = root.at("key").as_bin();
    if (invite.group_key.size() != 32) {
      error = "group key has an invalid length";
      return std::nullopt;
    }
    invite.label = root.at("n").as_str();
    invite.creator_pk = public_key_from(root.at("pk"));
    invite.creator_sign_pk = sign_key_from(root.at("spk"));
    invite.creator_name = root.at("cn").as_str();
    const Bytes& ep_bytes = root.at("ep").as_bin();
    msg::Value eps = msg::decode(ep_bytes);
    invite.endpoints = endpoints_from_value(&eps);
    invite.rendezvous = root.at("rv").as_str();
    if (is_zero(invite.creator_pk) || is_zero(invite.creator_sign_pk)) {
      error = "group invite contains a degenerate key";
      return std::nullopt;
    }
    return invite;
  } catch (const msg::Error& e) {
    error = std::string("malformed group invite: ") + e.what();
    return std::nullopt;
  }
}

}  // namespace jn
