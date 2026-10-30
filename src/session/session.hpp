#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/bytes.hpp"
#include "core/crypto.hpp"
#include "core/identity.hpp"

namespace jn {

enum class ChatKind : std::uint8_t {
  Chat = 0,
  Join = 1,
  Member = 2,
};

struct GroupMember {
  PublicKey pk{};
  SignPublicKey sign_pk{};
  std::string name;
};

struct DerivedSession {
  SessionId sid{};
  SecureBuffer i2r;
  SecureBuffer r2i;
};

// Derives directional keys and the session id from crypto_kx (identity keys)
// mixed with an ephemeral X25519 exchange. Both peers must reach the same
// session id or the handshake is rejected.
DerivedSession derive_session(bool initiator, const PublicKey& self_pk,
                              const SecureBuffer& self_sk, const PublicKey& peer_pk,
                              const SecureBuffer& self_ephemeral_sk,
                              const PublicKey& peer_ephemeral_pk);

struct Session {
  SessionId sid{};
  PublicKey peer_pk{};
  SignPublicKey peer_sign_pk{};
  std::string peer_name;
  std::string label;
  bool group = false;
  bool initiator = false;
  bool ratchet_leader = false;

  SecureBuffer key_i2r;
  SecureBuffer key_r2i;
  SecureBuffer prev_i2r;
  SecureBuffer prev_r2i;
  bool has_prev = false;
  std::chrono::steady_clock::time_point prev_expires{};

  std::uint64_t epoch = 0;
  std::uint64_t next_seq = 1;
  std::uint64_t messages_since_ratchet = 0;
  std::chrono::steady_clock::time_point established{};
  std::chrono::steady_clock::time_point last_ratchet{};

  std::vector<GroupMember> members;  // all known members, excluding self

  const SecureBuffer& send_key() const {
    if (group) return key_i2r;
    return initiator ? key_i2r : key_r2i;
  }
  const SecureBuffer& recv_key() const {
    if (group) return key_i2r;
    return initiator ? key_r2i : key_i2r;
  }
  bool should_rotate(std::chrono::steady_clock::time_point now) const;
};

struct ChatPayload {
  SessionId sid{};
  PublicKey from_pk{};
  std::string from_name;
  SignPublicKey sign_pk{};
  std::string text;
  std::uint64_t seq = 0;
  std::uint64_t epoch = 0;
  ChatKind kind = ChatKind::Chat;
  std::uint64_t msg_id = 0;
};

Bytes chat_signing_bytes(const SessionId& sid, const PublicKey& from, std::uint64_t msg_id,
                         std::uint64_t seq, std::uint64_t epoch, ChatKind kind,
                         const std::string& text);

// Encrypts and signs a chat payload with the current epoch's send key.
Bytes encrypt_chat_payload(const Identity& self, const Session& session,
                           const ChatPayload& payload);

// Decrypts with the current or previous epoch key and verifies the signature.
// expected_msg_id binds the packet header id to the signed plaintext.
std::optional<ChatPayload> decrypt_chat_payload(const Identity& self, const Session& session,
                                                const Bytes& ciphertext,
                                                std::uint64_t expected_msg_id,
                                                std::string& error);

// Leader-only X25519 ratchet. Produces the control ciphertext (under the old
// key) and returns the derived next keys; the caller applies them after send.
struct RatchetUpdate {
  Bytes control_payload;
  SecureBuffer new_i2r;
  SecureBuffer new_r2i;
  PublicKey ratchet_pk{};
  std::uint64_t new_epoch = 0;
};

std::optional<RatchetUpdate> prepare_ratchet(const Session& session,
                                             const PublicKey& self_pk,
                                             const PublicKey& peer_pk);

// Applies a peer's ratchet control. Returns false if it does not authenticate
// or does not extend the current epoch.
bool apply_ratchet(Session& session, const PublicKey& self_pk, const SecureBuffer& self_sk,
                   const PublicKey& peer_pk, const Bytes& control_payload,
                   std::string& error);

void commit_ratchet(Session& session, RatchetUpdate&& update,
                    std::chrono::steady_clock::time_point now);

void expire_previous_keys(Session& session, std::chrono::steady_clock::time_point now);

}  // namespace jn
