#include "session/session.hpp"

#include <algorithm>
#include <cstring>

#include "core/msgpack.hpp"

namespace jn {
namespace {

SecureBuffer hash_key(const std::string& context, const SecureBuffer& a,
                      const SecureBuffer& b, const Bytes& extra) {
  Bytes input;
  input.insert(input.end(), context.begin(), context.end());
  input.insert(input.end(), a.data(), a.data() + a.size());
  input.insert(input.end(), b.data(), b.data() + b.size());
  input.insert(input.end(), extra.begin(), extra.end());
  Bytes out = CryptoEngine::hash(input, 32);
  return SecureBuffer(out.data(), out.size());
}

SecureBuffer hash_ratchet_key(const std::string& context, const SecureBuffer& old_key,
                              const SecureBuffer& dh, const PublicKey& ratchet_pk) {
  Bytes input;
  input.insert(input.end(), context.begin(), context.end());
  input.insert(input.end(), old_key.data(), old_key.data() + old_key.size());
  input.insert(input.end(), dh.data(), dh.data() + dh.size());
  input.insert(input.end(), ratchet_pk.begin(), ratchet_pk.end());
  Bytes out = CryptoEngine::hash(input, 32);
  return SecureBuffer(out.data(), out.size());
}

std::string kind_to_string(ChatKind kind) {
  switch (kind) {
    case ChatKind::Chat: return "chat";
    case ChatKind::Join: return "join";
    case ChatKind::Member: return "member";
  }
  return "chat";
}

ChatKind kind_from_string(const std::string& text) {
  if (text == "join") return ChatKind::Join;
  if (text == "member") return ChatKind::Member;
  return ChatKind::Chat;
}

std::string ctx(const char* value) { return std::string("jargonet/") + value + "/v1"; }

}  // namespace

DerivedSession derive_session(bool initiator, const PublicKey& self_pk,
                              const SecureBuffer& self_sk, const PublicKey& peer_pk,
                              const SecureBuffer& self_ephemeral_sk,
                              const PublicKey& peer_ephemeral_pk) {
  SecureBuffer shared = CryptoEngine::scalarmult(self_ephemeral_sk, peer_ephemeral_pk);
  auto kx = initiator ? CryptoEngine::kx_client(self_pk, self_sk, peer_pk)
                      : CryptoEngine::kx_server(self_pk, self_sk, peer_pk);

  SecureBuffer i2r = initiator ? hash_key(ctx("msg-i2r"), kx.second, shared, {})
                              : hash_key(ctx("msg-i2r"), kx.first, shared, {});
  SecureBuffer r2i = initiator ? hash_key(ctx("msg-r2i"), kx.first, shared, {})
                              : hash_key(ctx("msg-r2i"), kx.second, shared, {});

  DerivedSession result;
  Bytes sid_input;
  const std::string sid_ctx = ctx("session-id");
  sid_input.insert(sid_input.end(), sid_ctx.begin(), sid_ctx.end());
  sid_input.insert(sid_input.end(), i2r.data(), i2r.data() + i2r.size());
  sid_input.insert(sid_input.end(), r2i.data(), r2i.data() + r2i.size());
  Bytes sid = CryptoEngine::hash(sid_input, kSessionIdBytes);
  std::memcpy(result.sid.data(), sid.data(), result.sid.size());
  result.i2r = std::move(i2r);
  result.r2i = std::move(r2i);
  return result;
}

bool Session::should_rotate(std::chrono::steady_clock::time_point now) const {
  if (group || !ratchet_leader) return false;
  return messages_since_ratchet >= 100 || now - last_ratchet >= std::chrono::hours(24);
}

Bytes chat_signing_bytes(const SessionId& sid, const PublicKey& from, std::uint64_t msg_id,
                         std::uint64_t seq, std::uint64_t epoch, ChatKind kind,
                         const std::string& text) {
  msg::Writer writer;
  writer.map(7);
  writer.str("sid");
  writer.bin(sid.data(), sid.size());
  writer.str("from");
  writer.bin(from.data(), from.size());
  writer.str("msg");
  writer.uint(msg_id);
  writer.str("seq");
  writer.uint(seq);
  writer.str("epoch");
  writer.uint(epoch);
  writer.str("kind");
  writer.str(kind_to_string(kind));
  writer.str("text");
  writer.str(text);
  return writer.take();
}

Bytes encrypt_chat_payload(const Identity& self, const Session& session,
                           const ChatPayload& payload) {
  if (payload.text.size() > 2048) throw CryptoError("message too long");
  Bytes signing = chat_signing_bytes(session.sid, self.pk, payload.msg_id, payload.seq,
                                     session.epoch, payload.kind, payload.text);
  Bytes signature = CryptoEngine::sign(self.sign_sk, signing.data(), signing.size());

  msg::Writer writer;
  writer.map(10);
  writer.str("sid");
  writer.bin(session.sid.data(), session.sid.size());
  writer.str("from");
  writer.bin(self.pk.data(), self.pk.size());
  writer.str("spk");
  writer.bin(self.sign_pk.data(), self.sign_pk.size());
  writer.str("name");
  writer.str(self.username);
  writer.str("text");
  writer.str(payload.text);
  writer.str("seq");
  writer.uint(payload.seq);
  writer.str("epoch");
  writer.uint(session.epoch);
  writer.str("kind");
  writer.str(kind_to_string(payload.kind));
  writer.str("msg");
  writer.uint(payload.msg_id);
  writer.str("sig");
  writer.bin(signature);
  Bytes plain = writer.take();

  Bytes out = CryptoEngine::secretbox_encrypt(session.send_key().data(), plain.data(), plain.size());
  CryptoEngine::wipe(plain.data(), plain.size());
  return out;
}

std::optional<ChatPayload> decrypt_chat_payload(const Identity& self, const Session& session,
                                                const Bytes& ciphertext,
                                                std::uint64_t expected_msg_id,
                                                std::string& error) {
  (void)self;
  Bytes plain;
  try {
    plain = CryptoEngine::secretbox_decrypt(session.recv_key().data(), ciphertext.data(),
                                            ciphertext.size());
  } catch (const CryptoError&) {
    if (!session.has_prev) {
      error = "message authentication failed";
      return std::nullopt;
    }
    const SecureBuffer& prev_recv = session.initiator ? session.prev_r2i : session.prev_i2r;
    try {
      plain = CryptoEngine::secretbox_decrypt(prev_recv.data(), ciphertext.data(),
                                              ciphertext.size());
    } catch (const CryptoError&) {
      error = "message authentication failed";
      return std::nullopt;
    }
  }

  try {
    msg::Value root = msg::decode(plain);
    CryptoEngine::wipe(plain.data(), plain.size());
    ChatPayload payload;
    payload.sid = root.at("sid").as_session_id();
    payload.from_pk = root.at("from").as_public_key();
    const Bytes& spk = root.at("spk").as_bin();
    if (spk.size() != kSignPublicKeyBytes) {
      error = "invalid signing key";
      return std::nullopt;
    }
    std::copy(spk.begin(), spk.end(), payload.sign_pk.begin());
    payload.from_name = root.at("name").as_str();
    payload.text = root.at("text").as_str();
    payload.seq = root.at("seq").as_uint();
    payload.epoch = root.at("epoch").as_uint();
    payload.kind = kind_from_string(root.at("kind").as_str());
    payload.msg_id = root.at("msg").as_uint();
    const Bytes& sig = root.at("sig").as_bin();

    if (payload.sid != session.sid) {
      error = "session id mismatch";
      return std::nullopt;
    }
    const bool current_epoch = payload.epoch == session.epoch;
    const bool previous_epoch = session.has_prev && payload.epoch + 1 == session.epoch;
    if (!current_epoch && !previous_epoch) {
      error = "message epoch mismatch";
      return std::nullopt;
    }
    if (payload.msg_id != expected_msg_id) {
      error = "message id mismatch";
      return std::nullopt;
    }

    if (!session.group) {
      if (payload.from_pk != session.peer_pk ||
          !std::equal(payload.sign_pk.begin(), payload.sign_pk.end(),
                      session.peer_sign_pk.begin())) {
        error = "sender is not the session peer";
        return std::nullopt;
      }
    }

    Bytes signing = chat_signing_bytes(payload.sid, payload.from_pk, payload.msg_id,
                                       payload.seq, payload.epoch, payload.kind, payload.text);
    if (!CryptoEngine::verify(payload.sign_pk, sig.data(), sig.size(), signing.data(),
                              signing.size())) {
      error = "invalid message signature";
      return std::nullopt;
    }
    return payload;
  } catch (const msg::Error& e) {
    error = std::string("malformed chat payload: ") + e.what();
    return std::nullopt;
  }
}

std::optional<RatchetUpdate> prepare_ratchet(const Session& session,
                                             const PublicKey& self_pk,
                                             const PublicKey& peer_pk) {
  if (session.group || !session.ratchet_leader) return std::nullopt;

  auto ephemeral = CryptoEngine::generate_box_keypair();
  SecureBuffer dh = CryptoEngine::scalarmult(ephemeral.sk, peer_pk);
  RatchetUpdate update;
  update.new_i2r = hash_ratchet_key(ctx("ratchet-i2r"), session.key_i2r, dh, ephemeral.pk);
  update.new_r2i = hash_ratchet_key(ctx("ratchet-r2i"), session.key_r2i, dh, ephemeral.pk);
  update.ratchet_pk = ephemeral.pk;
  update.new_epoch = session.epoch + 1;

  msg::Writer writer;
  writer.map(5);
  writer.str("sid");
  writer.bin(session.sid.data(), session.sid.size());
  writer.str("from");
  writer.bin(self_pk.data(), self_pk.size());
  writer.str("epoch");
  writer.uint(update.new_epoch);
  writer.str("rpk");
  writer.bin(ephemeral.pk.data(), ephemeral.pk.size());
  writer.str("v");
  writer.uint(1);
  Bytes plain = writer.take();
  update.control_payload =
      CryptoEngine::secretbox_encrypt(session.send_key().data(), plain.data(), plain.size());
  CryptoEngine::wipe(plain.data(), plain.size());
  return update;
}

bool apply_ratchet(Session& session, const PublicKey& self_pk, const SecureBuffer& self_sk,
                   const PublicKey& peer_pk, const Bytes& control_payload,
                   std::string& error) {
  (void)self_pk;
  Bytes plain;
  bool decrypted = false;
  try {
    plain = CryptoEngine::secretbox_decrypt(session.recv_key().data(), control_payload.data(),
                                            control_payload.size());
    decrypted = true;
  } catch (const CryptoError&) {
    if (session.has_prev) {
      try {
        const SecureBuffer& prev_recv = session.initiator ? session.prev_r2i : session.prev_i2r;
        plain = CryptoEngine::secretbox_decrypt(prev_recv.data(), control_payload.data(),
                                                control_payload.size());
        decrypted = true;
      } catch (const CryptoError&) {
      }
    }
  }
  if (!decrypted) {
    error = "ratchet control failed authentication";
    return false;
  }

  try {
    msg::Value root = msg::decode(plain);
    CryptoEngine::wipe(plain.data(), plain.size());
    if (root.at("sid").as_session_id() != session.sid) {
      error = "ratchet session mismatch";
      return false;
    }
    if (root.at("from").as_public_key() != peer_pk) {
      error = "ratchet sender mismatch";
      return false;
    }
    const std::uint64_t epoch = root.at("epoch").as_uint();
    if (epoch != session.epoch + 1) {
      error = "unexpected ratchet epoch";
      return false;
    }
    const Bytes& rpk_bytes = root.at("rpk").as_bin();
    if (rpk_bytes.size() != kPublicKeyBytes) {
      error = "invalid ratchet public key";
      return false;
    }
    PublicKey rpk{};
    std::copy(rpk_bytes.begin(), rpk_bytes.end(), rpk.begin());
    if (!CryptoEngine::valid_public_key(rpk)) {
      error = "degenerate ratchet public key";
      return false;
    }

    SecureBuffer dh = CryptoEngine::scalarmult(self_sk, rpk);
    SecureBuffer new_i2r = hash_ratchet_key(ctx("ratchet-i2r"), session.key_i2r, dh, rpk);
    SecureBuffer new_r2i = hash_ratchet_key(ctx("ratchet-r2i"), session.key_r2i, dh, rpk);

    const auto now = std::chrono::steady_clock::now();
    session.prev_i2r = std::move(session.key_i2r);
    session.prev_r2i = std::move(session.key_r2i);
    session.has_prev = true;
    session.prev_expires = now + std::chrono::minutes(2);
    session.key_i2r = std::move(new_i2r);
    session.key_r2i = std::move(new_r2i);
    session.epoch = epoch;
    session.messages_since_ratchet = 0;
    session.last_ratchet = now;
    return true;
  } catch (const msg::Error& e) {
    error = std::string("malformed ratchet control: ") + e.what();
    return false;
  }
}

void commit_ratchet(Session& session, RatchetUpdate&& update,
                    std::chrono::steady_clock::time_point now) {
  session.prev_i2r = std::move(session.key_i2r);
  session.prev_r2i = std::move(session.key_r2i);
  session.has_prev = true;
  session.prev_expires = now + std::chrono::minutes(2);
  session.key_i2r = std::move(update.new_i2r);
  session.key_r2i = std::move(update.new_r2i);
  session.epoch = update.new_epoch;
  session.messages_since_ratchet = 0;
  session.last_ratchet = now;
}

void expire_previous_keys(Session& session, std::chrono::steady_clock::time_point now) {
  if (session.has_prev && now >= session.prev_expires) {
    session.prev_i2r.wipe();
    session.prev_r2i.wipe();
    session.has_prev = false;
  }
}

}  // namespace jn
