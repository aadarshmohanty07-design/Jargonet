#pragma once

#include <optional>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "net/endpoint.hpp"

namespace jn {

struct ContactInvite {
  std::string username;
  PublicKey pk{};
  SignPublicKey sign_pk{};
  std::vector<Endpoint> endpoints;
  std::string rendezvous;
};

struct GroupInvite {
  SessionId sid{};
  Bytes group_key;
  std::string label;
  PublicKey creator_pk{};
  SignPublicKey creator_sign_pk{};
  std::string creator_name;
  std::vector<Endpoint> endpoints;
  std::string rendezvous;
};

std::string encode_contact_invite(const ContactInvite& invite);
std::optional<ContactInvite> decode_contact_invite(std::string_view code, std::string& error);

std::string encode_group_invite(const GroupInvite& invite);
std::optional<GroupInvite> decode_group_invite(std::string_view code, std::string& error);

}  // namespace jn
