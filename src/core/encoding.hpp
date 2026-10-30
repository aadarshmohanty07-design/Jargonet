#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "core/bytes.hpp"

namespace jn {

std::string hex_encode(const std::uint8_t* data, std::size_t size);
std::string hex_encode(const Bytes& data);
std::optional<Bytes> hex_decode(std::string_view text);

std::string base64url_encode(const std::uint8_t* data, std::size_t size);
std::string base64url_encode(const Bytes& data);
std::optional<Bytes> base64url_decode(std::string_view text);

// Fingerprint of an X25519 identity key: BLAKE2b-256 truncated to 16 bytes.
std::string fingerprint(const PublicKey& pk);
std::string pretty_fingerprint(const PublicKey& pk);

std::string trim(std::string_view text);
bool iequals(std::string_view a, std::string_view b);

}  // namespace jn
