#include "net/stun.hpp"

#include <chrono>
#include <cstring>

#include "core/crypto.hpp"
#include "net/udp_socket.hpp"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

namespace jn {
namespace {

constexpr std::uint32_t kMagicCookie = 0x2112A442;
constexpr std::uint16_t kBindingRequest = 0x0001;
constexpr std::uint16_t kBindingSuccess = 0x0101;
constexpr std::uint16_t kAttrMappedAddress = 0x0001;
constexpr std::uint16_t kAttrXorMappedAddress = 0x0020;

std::uint16_t read_u16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t read_u32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

}  // namespace

Bytes build_stun_binding_request(const StunTransactionId& transaction) {
  Bytes out(20);
  out[0] = 0;
  out[1] = static_cast<std::uint8_t>(kBindingRequest);
  out[2] = 0;
  out[3] = 0;
  out[4] = 0x21;
  out[5] = 0x12;
  out[6] = 0xA4;
  out[7] = 0x42;
  std::memcpy(out.data() + 8, transaction.data(), transaction.size());
  return out;
}

std::optional<Endpoint> parse_stun_binding_response(const std::uint8_t* data, std::size_t size,
                                                    const StunTransactionId* expected) {
  if (!data || size < 20) return std::nullopt;
  const std::uint16_t type = read_u16(data);
  const std::uint16_t length = read_u16(data + 2);
  if (type != kBindingSuccess) return std::nullopt;
  if (read_u32(data + 4) != kMagicCookie) return std::nullopt;
  if (expected && std::memcmp(data + 8, expected->data(), expected->size()) != 0) {
    return std::nullopt;
  }
  if (static_cast<std::size_t>(length) + 20 > size) return std::nullopt;

  std::optional<Endpoint> fallback;
  std::size_t offset = 20;
  const std::size_t end = 20 + length;
  while (offset + 4 <= end) {
    const std::uint16_t attr_type = read_u16(data + offset);
    const std::uint16_t attr_len = read_u16(data + offset + 2);
    offset += 4;
    if (offset + attr_len > end) return std::nullopt;

    if ((attr_type == kAttrXorMappedAddress || attr_type == kAttrMappedAddress) && attr_len >= 8) {
      const std::uint8_t family = data[offset + 1];
      if (family == 0x01) {
        std::uint16_t port = read_u16(data + offset + 2);
        std::uint32_t ip = read_u32(data + offset + 4);
        if (attr_type == kAttrXorMappedAddress) {
          port ^= static_cast<std::uint16_t>(kMagicCookie >> 16);
          ip ^= kMagicCookie;
        }
        char buffer[INET_ADDRSTRLEN] = {0};
        in_addr addr{};
        addr.s_addr = htonl(ip);
        if (::inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
          Endpoint ep{std::string(buffer), port};
          if (attr_type == kAttrXorMappedAddress) return ep;
          fallback = ep;
        }
      }
    }
    offset += (attr_len + 3) & ~std::size_t(3);
  }
  return fallback;
}

std::optional<Endpoint> stun_discover(UdpSocket& socket, const Endpoint& server,
                                      int timeout_ms) {
  if (!socket.is_open() || !server.valid()) return std::nullopt;

  StunTransactionId txn{};
  auto random = CryptoEngine::random_bytes(txn.size());
  std::memcpy(txn.data(), random.data(), txn.size());
  Bytes request = build_stun_binding_request(txn);
  if (!socket.send_to(server, request)) return std::nullopt;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                               deadline - std::chrono::steady_clock::now())
                               .count();
    if (remaining <= 0) break;
    if (!socket.wait_readable(static_cast<int>(remaining))) break;
    auto datagram = socket.recv_from();
    if (!datagram) break;
    auto mapped = parse_stun_binding_response(datagram->data.data(), datagram->data.size(), &txn);
    if (mapped) return mapped;
  }
  return std::nullopt;
}

}  // namespace jn
