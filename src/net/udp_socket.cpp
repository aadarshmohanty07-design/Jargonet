#include "net/udp_socket.hpp"

#include <cstring>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace jn {
namespace {

#ifdef _WIN32
bool ensure_winsock(std::string& error) {
  static const bool ready = [] {
    WSADATA data{};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  if (!ready) error = "WSAStartup failed";
  return ready;
}

void close_handle(SOCKET handle) {
  if (handle != INVALID_SOCKET) closesocket(handle);
}
#else
void close_handle(int handle) {
  if (handle >= 0) ::close(handle);
}
#endif

}  // namespace

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : handle_(other.handle_), bound_port_(other.bound_port_) {
#ifdef _WIN32
  other.handle_ = INVALID_SOCKET;
#else
  other.handle_ = -1;
#endif
  other.bound_port_ = 0;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    bound_port_ = other.bound_port_;
#ifdef _WIN32
    other.handle_ = INVALID_SOCKET;
#else
    other.handle_ = -1;
#endif
    other.bound_port_ = 0;
  }
  return *this;
}

bool UdpSocket::open(std::uint16_t port, std::string& error,
                      const UdpSocketOptions& options) {
  close();
#ifdef _WIN32
  if (!ensure_winsock(error)) return false;
  handle_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (handle_ == INVALID_SOCKET) {
    error = "cannot create UDP socket";
    return false;
  }
  BOOL exclusive = FALSE;
  setsockopt(handle_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
             sizeof(exclusive));
  if (options.reuse_address) {
    BOOL reuse = TRUE;
    setsockopt(handle_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
               sizeof(reuse));
  }
#else
  handle_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (handle_ < 0) {
    error = "cannot create UDP socket";
    return false;
  }
  int reuse = 1;
  setsockopt(handle_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
  if (options.reuse_port) {
    setsockopt(handle_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
  }
#endif
#endif
  if (options.broadcast) {
    int broadcast = 1;
#ifdef _WIN32
    if (setsockopt(handle_, SOL_SOCKET, SO_BROADCAST,
                   reinterpret_cast<const char*>(&broadcast), sizeof(broadcast)) != 0) {
#else
    if (setsockopt(handle_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) != 0) {
#endif
      error = "cannot enable UDP broadcast";
      close();
      return false;
    }
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (::bind(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    error = "cannot bind UDP port " + std::to_string(port);
    close();
    return false;
  }

#ifdef _WIN32
  u_long nonblocking = 1;
  if (ioctlsocket(handle_, FIONBIO, &nonblocking) != 0) {
    error = "cannot make UDP socket non-blocking";
    close();
    return false;
  }
#else
  int flags = fcntl(handle_, F_GETFL, 0);
  if (flags < 0 || fcntl(handle_, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = "cannot make UDP socket non-blocking";
    close();
    return false;
  }
#endif

  sockaddr_in local{};
  socklen_t len = sizeof(local);
  if (getsockname(handle_, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
    bound_port_ = ntohs(local.sin_port);
  } else {
    bound_port_ = port;
  }
  return true;
}

void UdpSocket::close() {
  if (is_open()) {
    close_handle(handle_);
#ifdef _WIN32
    handle_ = INVALID_SOCKET;
#else
    handle_ = -1;
#endif
  }
  bound_port_ = 0;
}

bool UdpSocket::is_open() const {
#ifdef _WIN32
  return handle_ != INVALID_SOCKET;
#else
  return handle_ >= 0;
#endif
}

std::uint16_t UdpSocket::local_port() const { return bound_port_; }

std::optional<Endpoint> UdpSocket::resolve_ipv4(const std::string& host, std::uint16_t port) {
  in_addr addr{};
  if (::inet_pton(AF_INET, host.c_str(), &addr) == 1) {
    return Endpoint{host, port};
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* result = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) return std::nullopt;
  std::optional<Endpoint> found;
  if (result) {
    char buffer[INET_ADDRSTRLEN] = {0};
    auto* sin = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    if (::inet_ntop(AF_INET, &sin->sin_addr, buffer, sizeof(buffer))) {
      found = Endpoint{std::string(buffer), port};
    }
  }
  ::freeaddrinfo(result);
  return found;
}

bool UdpSocket::send_to(const Endpoint& endpoint, const std::uint8_t* data, std::size_t size) {
  if (!is_open() || !endpoint.valid() || (!data && size > 0)) return false;
  auto resolved = resolve_ipv4(endpoint.host, endpoint.port);
  if (!resolved) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(resolved->port);
  if (::inet_pton(AF_INET, resolved->host.c_str(), &addr.sin_addr) != 1) return false;
  const int sent = static_cast<int>(::sendto(
      handle_, reinterpret_cast<const char*>(data), static_cast<int>(size), 0,
      reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)));
  return sent == static_cast<int>(size);
}

bool UdpSocket::send_to(const Endpoint& endpoint, const Bytes& data) {
  return send_to(endpoint, data.data(), data.size());
}

std::optional<Datagram> UdpSocket::recv_from() {
  if (!is_open()) return std::nullopt;
  std::uint8_t buffer[65535];
  sockaddr_in from{};
  socklen_t from_len = sizeof(from);
  const int received = static_cast<int>(::recvfrom(
      handle_, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
      reinterpret_cast<sockaddr*>(&from), &from_len));
  if (received <= 0) return std::nullopt;

  char host[INET_ADDRSTRLEN] = {0};
  if (!::inet_ntop(AF_INET, &from.sin_addr, host, sizeof(host))) return std::nullopt;
  Datagram datagram;
  datagram.from = Endpoint{std::string(host), ntohs(from.sin_port)};
  datagram.data.assign(buffer, buffer + received);
  return datagram;
}

bool UdpSocket::wait_readable(int timeout_ms) {
  if (!is_open()) return false;
#ifdef _WIN32
  fd_set set;
  FD_ZERO(&set);
  FD_SET(handle_, &set);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  const int result = ::select(0, &set, nullptr, nullptr, &tv);
  return result > 0 && FD_ISSET(handle_, &set);
#else
  pollfd pfd{};
  pfd.fd = handle_;
  pfd.events = POLLIN;
  const int result = ::poll(&pfd, 1, timeout_ms);
  return result > 0 && (pfd.revents & POLLIN);
#endif
}

}  // namespace jn
