#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/identity.hpp"
#include "core/packet.hpp"
#include "routing/onion.hpp"
#include "session/session.hpp"

namespace jn {

class MessageDispatcher {
 public:
  explicit MessageDispatcher(const Identity& identity) : identity_(identity) {}

  Packet build_direct(const Session& session, ChatKind kind, const std::string& text,
                      std::uint64_t msg_id, std::uint64_t seq, std::uint8_t flags) const;

  std::optional<BuiltOnion> build_onion(const Session& session, ChatKind kind,
                                        const std::string& text, std::uint64_t msg_id,
                                        std::uint64_t seq, const Endpoint& recipient,
                                        const std::vector<OnionHop>& path,
                                        std::string& error) const;

  std::optional<ChatPayload> open(const Session& session, const Packet& packet,
                                  std::string& error) const;

 private:
  const Identity& identity_;
};

}  // namespace jn
