#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "core/crypto.hpp"

namespace jn {

class StoreError : public std::runtime_error {
 public:
  explicit StoreError(const std::string& what) : std::runtime_error(what) {}
};

struct StoredContact {
  PublicKey pk{};
  SignPublicKey sign_pk{};
  std::string username;
};

struct StoredSession {
  SessionId sid{};
  PublicKey peer_pk{};
  SignPublicKey peer_sign_pk{};
  std::string label;
  bool group = false;
  bool initiator = false;
  std::vector<StoredContact> members;
};

struct StoredMessage {
  SessionId sid{};
  PublicKey from_pk{};
  std::string from_name;
  bool outgoing = false;
  std::string text;
  std::uint64_t seq = 0;
};

// Encrypted, append-only-from-the-app's-perspective local database.
// The file is a libsodium secretbox container keyed by Argon2id(password).
// Only session ids, peer fingerprints/names and message text are stored;
// timestamps, IP addresses and relay paths are deliberately not persisted.
class LocalStore {
 public:
  static constexpr const char* kStoreFileName = "store.jnst";

  LocalStore(const std::filesystem::path& data_dir, const std::string& password,
             bool fast_kdf = false);
  ~LocalStore();

  LocalStore(const LocalStore&) = delete;
  LocalStore& operator=(const LocalStore&) = delete;

  const std::vector<StoredContact>& contacts() const { return contacts_; }
  const std::vector<StoredSession>& sessions() const { return sessions_; }

  std::vector<StoredMessage> messages(const SessionId& sid, std::size_t limit = 500) const;
  std::optional<StoredContact> find_contact(const PublicKey& pk) const;
  std::optional<StoredSession> find_session(const SessionId& sid) const;

  void upsert_contact(const StoredContact& contact);
  void upsert_session(const StoredSession& session);
  void append_message(const StoredMessage& message);
  void save();

  static void wipe_files(const std::filesystem::path& data_dir);

 private:
  Bytes serialise() const;

  std::filesystem::path dir_;
  std::filesystem::path path_;
  SecureBuffer key_;
  std::uint8_t salt_[kPwhashSaltBytes]{};
  std::uint64_t ops_limit_ = 0;
  std::size_t mem_limit_ = 0;
  std::vector<StoredContact> contacts_;
  std::vector<StoredSession> sessions_;
  std::vector<StoredMessage> messages_;
};

}  // namespace jn
