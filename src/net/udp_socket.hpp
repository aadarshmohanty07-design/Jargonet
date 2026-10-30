#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "net/endpoint.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace jn {

class UdpError : public std::runtime_error {
 public:
  explicit UdpError(const std::string& what) : std::runtime_error(what) {}
};

struct Datagram {
  Endpoint from;
  Bytes data;
};

struct UdpSocketOptions {
  bool reuse_address = false;
  bool reuse_port = false;
  bool broadcast = false;
};

class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket();

  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;
  UdpSocket(UdpSocket&& other) noexcept;
  UdpSocket& operator=(UdpSocket&& other) noexcept;

  // Binds on all IPv4 interfaces. port 0 selects an ephemeral port.
  // reuse_address/reuse_port are for the shared discovery port; broadcast
  // enables SO_BROADCAST for limited-broadcast HELLOs.
  bool open(std::uint16_t port, std::string& error,
            const UdpSocketOptions& options = {});
  void close();

  bool is_open() const;
  std::uint16_t local_port() const;

  bool send_to(const Endpoint& endpoint, const std::uint8_t* data, std::size_t size);
  bool send_to(const Endpoint& endpoint, const Bytes& data);

  std::optional<Datagram> recv_from();
  bool wait_readable(int timeout_ms);

  static std::optional<Endpoint> resolve_ipv4(const std::string& host, std::uint16_t port);

 private:
#ifdef _WIN32
  SOCKET handle_ = INVALID_SOCKET;
#else
  int handle_ = -1;
#endif
  std::uint16_t bound_port_ = 0;
};

}  // namespace jn
