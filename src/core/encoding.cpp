#include "core/encoding.hpp"

#include <algorithm>
#include <cctype>

#include "core/crypto.hpp"

namespace jn {
namespace {

constexpr char kBase64Url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

}  // namespace

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

std::string hex_encode(const Bytes& data) {
  return hex_encode(data.data(), data.size());
}

std::optional<Bytes> hex_decode(std::string_view text) {
  if (text.size() % 2 != 0) return std::nullopt;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  Bytes out(text.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    int hi = nibble(text[2 * i]);
    int lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return out;
}

std::string base64url_encode(const std::uint8_t* data, std::size_t size) {
  std::string out;
  out.reserve((size * 4 + 2) / 3);
  std::size_t i = 0;
  while (i + 3 <= size) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                      static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kBase64Url[(v >> 18) & 0x3f]);
    out.push_back(kBase64Url[(v >> 12) & 0x3f]);
    out.push_back(kBase64Url[(v >> 6) & 0x3f]);
    out.push_back(kBase64Url[v & 0x3f]);
    i += 3;
  }
  if (i + 1 == size) {
    std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
    out.push_back(kBase64Url[(v >> 18) & 0x3f]);
    out.push_back(kBase64Url[(v >> 12) & 0x3f]);
  } else if (i + 2 == size) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8);
    out.push_back(kBase64Url[(v >> 18) & 0x3f]);
    out.push_back(kBase64Url[(v >> 12) & 0x3f]);
    out.push_back(kBase64Url[(v >> 6) & 0x3f]);
  }
  return out;
}

std::string base64url_encode(const Bytes& data) {
  return base64url_encode(data.data(), data.size());
}

std::optional<Bytes> base64url_decode(std::string_view text) {
  while (!text.empty() && text.back() == '=') text.remove_suffix(1);
  if (text.size() % 4 == 1) return std::nullopt;
  Bytes out;
  out.reserve(text.size() * 3 / 4);
  std::uint32_t buffer = 0;
  int bits = 0;
  for (char c : text) {
    int v = base64_value(c);
    if (v < 0) return std::nullopt;
    buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xff));
    }
  }
  return out;
}

std::string fingerprint(const PublicKey& pk) {
  Bytes fp = CryptoEngine::hash(pk.data(), pk.size(), kSessionIdBytes);
  std::string hex = hex_encode(fp);
  std::transform(hex.begin(), hex.end(), hex.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return hex;
}

std::string pretty_fingerprint(const PublicKey& pk) {
  std::string fp = fingerprint(pk);
  std::string out;
  out.reserve(fp.size() + fp.size() / 4);
  for (std::size_t i = 0; i < fp.size(); ++i) {
    if (i != 0 && i % 4 == 0) out.push_back('-');
    out.push_back(fp[i]);
  }
  return out;
}

std::string trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
  return std::string(text.substr(begin, end - begin));
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace jn
