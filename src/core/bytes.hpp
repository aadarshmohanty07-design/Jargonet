#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace jn {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kPublicKeyBytes = 32;
constexpr std::size_t kSecretKeyBytes = 32;
constexpr std::size_t kSignPublicKeyBytes = 32;
constexpr std::size_t kSignSecretKeyBytes = 64;
constexpr std::size_t kSessionIdBytes = 16;
constexpr std::size_t kNonceBytes = 24;
constexpr std::size_t kHashBytes = 32;
constexpr std::size_t kPwhashSaltBytes = 16;

using PublicKey = std::array<std::uint8_t, kPublicKeyBytes>;
using SignPublicKey = std::array<std::uint8_t, kSignPublicKeyBytes>;
using SessionId = std::array<std::uint8_t, kSessionIdBytes>;
using Nonce = std::array<std::uint8_t, kNonceBytes>;

constexpr PublicKey kZeroPublicKey{};
constexpr SessionId kZeroSessionId{};

inline bool is_zero(const PublicKey& key) {
  for (auto b : key) {
    if (b != 0) return false;
  }
  return true;
}

inline bool is_zero(const SessionId& id) {
  for (auto b : id) {
    if (b != 0) return false;
  }
  return true;
}

inline bool equal(const PublicKey& a, const PublicKey& b) { return a == b; }

inline bool equal(const SessionId& a, const SessionId& b) { return a == b; }

}  // namespace jn
