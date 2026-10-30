#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace jn {

struct Endpoint {
  std::string host;
  std::uint16_t port = 0;

  bool valid() const { return !host.empty() && port != 0; }
  std::string to_string() const;

  static std::optional<Endpoint> parse(std::string_view text);

  bool operator==(const Endpoint& other) const {
    return port == other.port && host == other.host;
  }
  bool operator!=(const Endpoint& other) const { return !(*this == other); }
};

struct EndpointHash {
  std::size_t operator()(const Endpoint& ep) const noexcept;
};

// Local IPv4 addresses that a peer might be able to reach, including loopback.
std::vector<Endpoint> local_candidates(std::uint16_t port);

}  // namespace jn
