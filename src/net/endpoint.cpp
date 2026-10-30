#include "net/endpoint.hpp"

#include <algorithm>

#include "core/encoding.hpp"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace jn {

std::string Endpoint::to_string() const {
  if (host.find(':') != std::string::npos) return "[" + host + "]:" + std::to_string(port);
  return host + ":" + std::to_string(port);
}

std::optional<Endpoint> Endpoint::parse(std::string_view text) {
  if (text.empty()) return std::nullopt;
  std::string_view host;
  std::string_view port_text;
  if (text.front() == '[') {
    auto close = text.find(']');
    if (close == std::string_view::npos || close + 2 > text.size() || text[close + 1] != ':') {
      return std::nullopt;
    }
    host = text.substr(1, close - 1);
    port_text = text.substr(close + 2);
  } else {
    auto colon = text.rfind(':');
    if (colon == std::string_view::npos || text.find(':') != colon) return std::nullopt;
    host = text.substr(0, colon);
    port_text = text.substr(colon + 1);
  }
  if (host.empty() || port_text.empty()) return std::nullopt;
  unsigned long value = 0;
  for (char c : port_text) {
    if (c < '0' || c > '9') return std::nullopt;
    value = value * 10 + static_cast<unsigned long>(c - '0');
    if (value > 65535) return std::nullopt;
  }
  if (value == 0) return std::nullopt;
  return Endpoint{std::string(host), static_cast<std::uint16_t>(value)};
}

std::size_t EndpointHash::operator()(const Endpoint& ep) const noexcept {
  return std::hash<std::string>{}(ep.host) ^ (static_cast<std::size_t>(ep.port) << 16);
}

std::vector<Endpoint> local_candidates(std::uint16_t port) {
  std::vector<Endpoint> out;
  if (port == 0) return out;

  char hostname[256] = {0};
  if (::gethostname(hostname, sizeof(hostname) - 1) != 0) {
    out.push_back({"127.0.0.1", port});
    return out;
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* result = nullptr;
  if (::getaddrinfo(hostname, nullptr, &hints, &result) == 0) {
    for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
      char buffer[INET_ADDRSTRLEN] = {0};
      auto* addr = reinterpret_cast<sockaddr_in*>(it->ai_addr);
      if (::inet_ntop(AF_INET, &addr->sin_addr, buffer, sizeof(buffer))) {
        Endpoint ep{std::string(buffer), port};
        if (ep.host != "127.0.0.1" &&
            std::find(out.begin(), out.end(), ep) == out.end()) {
          out.push_back(ep);
        }
      }
    }
    ::freeaddrinfo(result);
  }
  out.push_back({"127.0.0.1", port});
  return out;
}

}  // namespace jn
