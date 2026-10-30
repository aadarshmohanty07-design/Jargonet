#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

#include "core/bytes.hpp"
#include "core/crypto.hpp"

namespace jn {

class IdentityError : public std::runtime_error {
 public:
  explicit IdentityError(const std::string& what) : std::runtime_error(what) {}
};

struct Identity {
  std::string username;
  PublicKey pk{};
  SignPublicKey sign_pk{};
  SecureBuffer sk;
  SecureBuffer sign_sk;

  Identity() = default;
  Identity(const Identity&) = delete;
  Identity& operator=(const Identity&) = delete;
  Identity(Identity&&) noexcept = default;
  Identity& operator=(Identity&&) noexcept = default;

  std::string fingerprint() const;
  std::string short_fingerprint() const;
};

class IdentityManager {
 public:
  static constexpr const char* kIdentityFileName = "identity.jnid";
  static constexpr std::size_t kMinPasswordLength = 8;
  static constexpr std::size_t kMaxPasswordLength = 1024;

  static bool exists(const std::filesystem::path& data_dir);

  static Identity create(const std::filesystem::path& data_dir, const std::string& username,
                         const std::string& password);

  static Identity unlock(const std::filesystem::path& data_dir, const std::string& password);

  static void wipe(const std::filesystem::path& data_dir);

  static void validate_username(const std::string& username);
  static void validate_password(const std::string& password);
};

}  // namespace jn
