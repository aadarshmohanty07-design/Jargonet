#include <string>

#include "core/msgpack.hpp"
#include "core/packet.hpp"
#include "session/session.hpp"
#include "test_util.hpp"

using namespace jn;

namespace {

Session make_session(const Identity& self, const Identity& peer, const DerivedSession& keys,
                     bool initiator) {
  Session session;
  session.sid = keys.sid;
  session.peer_pk = peer.pk;
  session.peer_sign_pk = peer.sign_pk;
  session.peer_name = peer.username;
  session.label = peer.username;
  session.initiator = initiator;
  session.ratchet_leader = initiator;
  session.key_i2r = SecureBuffer(keys.i2r.data(), keys.i2r.size());
  session.key_r2i = SecureBuffer(keys.r2i.data(), keys.r2i.size());
  session.established = std::chrono::steady_clock::now();
  session.last_ratchet = session.established;
  (void)self;
  return session;
}

ChatPayload payload_for(const Session& session, const Identity& self, const std::string& text,
                        std::uint64_t seq, std::uint64_t msg_id) {
  ChatPayload payload;
  payload.sid = session.sid;
  payload.from_pk = self.pk;
  payload.from_name = self.username;
  payload.sign_pk = self.sign_pk;
  payload.text = text;
  payload.seq = seq;
  payload.epoch = session.epoch;
  payload.kind = ChatKind::Chat;
  payload.msg_id = msg_id;
  return payload;
}

}  // namespace

void run() {
  auto alice = jntest::make_identity("alice");
  auto bob = jntest::make_identity("bob");

  auto a_eph = CryptoEngine::generate_box_keypair();
  auto b_eph = CryptoEngine::generate_box_keypair();
  DerivedSession ka = derive_session(true, alice.pk, alice.sk, bob.pk, a_eph.sk, b_eph.pk);
  DerivedSession kb = derive_session(false, bob.pk, bob.sk, alice.pk, b_eph.sk, a_eph.pk);
  CHECK(ka.sid == kb.sid);
  CHECK(CryptoEngine::constant_time_equal(ka.i2r.data(), kb.i2r.data(), 32));
  CHECK(CryptoEngine::constant_time_equal(ka.r2i.data(), kb.r2i.data(), 32));

  Session sa = make_session(alice, bob, ka, true);
  Session sb = make_session(bob, alice, kb, false);
  CHECK(sa.sid == sb.sid);
  CHECK(sa.epoch == 0 && sb.epoch == 0);

  const std::uint64_t first_id = 1001;
  Bytes ciphertext = encrypt_chat_payload(alice, sa, payload_for(sa, alice, "hello bob", 1, first_id));
  std::string error;
  auto opened = decrypt_chat_payload(bob, sb, ciphertext, first_id, error);
  CHECK(opened.has_value());
  if (opened) {
    CHECK(opened->text == "hello bob");
    CHECK(opened->from_pk == alice.pk);
    CHECK(opened->from_name == "alice");
    CHECK(opened->msg_id == first_id);
    CHECK(opened->seq == 1);
    CHECK(opened->kind == ChatKind::Chat);
  }

  // Header message id is bound to the signed plaintext.
  CHECK(!decrypt_chat_payload(bob, sb, ciphertext, first_id + 1, error).has_value());

  // Reply direction.
  const std::uint64_t reply_id = 2002;
  Bytes reply = encrypt_chat_payload(bob, sb, payload_for(sb, bob, "hi alice", 1, reply_id));
  auto opened_reply = decrypt_chat_payload(alice, sa, reply, reply_id, error);
  CHECK(opened_reply.has_value());
  if (opened_reply) CHECK(opened_reply->text == "hi alice");

  // Tampering and wrong sessions.
  Bytes tampered = ciphertext;
  tampered.back() ^= 0x01;
  CHECK(!decrypt_chat_payload(bob, sb, tampered, first_id, error).has_value());

  auto other_eph = CryptoEngine::generate_box_keypair();
  DerivedSession wrong = derive_session(false, bob.pk, bob.sk, alice.pk, other_eph.sk, a_eph.pk);
  Session wrong_session = make_session(bob, alice, wrong, false);
  CHECK(!decrypt_chat_payload(bob, wrong_session, ciphertext, first_id, error).has_value());

  // Signature tampering is detected even when the symmetric box is valid.
  Bytes plain = CryptoEngine::secretbox_decrypt(sa.send_key().data(), ciphertext.data(),
                                                ciphertext.size());
  msg::Value root = msg::decode(plain);
  for (auto& [key, value] : root.map) {
    if (key == "sig") value.bin[0] ^= 1;
  }
  Bytes with_bad_sig = msg::encode(root);
  Bytes encrypted_bad_sig = CryptoEngine::secretbox_encrypt(sa.send_key().data(),
                                                            with_bad_sig.data(), with_bad_sig.size());
  CHECK(!decrypt_chat_payload(bob, sb, encrypted_bad_sig, first_id, error).has_value());

  // Ratchet: the initiator is the leader.
  CHECK(sa.should_rotate(std::chrono::steady_clock::now()) == false);
  CHECK(!prepare_ratchet(sb, bob.pk, alice.pk).has_value());
  auto ratchet = prepare_ratchet(sa, alice.pk, bob.pk);
  CHECK(ratchet.has_value());
  if (ratchet) {
    Bytes old_ciphertext = ciphertext;
    std::string ratchet_error;
    CHECK(apply_ratchet(sb, bob.pk, bob.sk, alice.pk, ratchet->control_payload, ratchet_error));
    commit_ratchet(sa, std::move(*ratchet), std::chrono::steady_clock::now());
    CHECK(sa.epoch == 1);
    CHECK(sb.epoch == 1);
    CHECK(CryptoEngine::constant_time_equal(sa.key_i2r.data(), sb.key_i2r.data(), 32));
    CHECK(CryptoEngine::constant_time_equal(sa.key_r2i.data(), sb.key_r2i.data(), 32));

    const std::uint64_t after_id = 3003;
    Bytes after = encrypt_chat_payload(alice, sa, payload_for(sa, alice, "after ratchet", 2, after_id));
    auto opened_after = decrypt_chat_payload(bob, sb, after, after_id, error);
    CHECK(opened_after.has_value());
    if (opened_after) CHECK(opened_after->text == "after ratchet");

    // The previous epoch key remains available briefly for messages in flight.
    CHECK(sb.has_prev);
    auto old_open = decrypt_chat_payload(bob, sb, old_ciphertext, first_id, error);
    CHECK(old_open.has_value());

    // A stale control cannot be replayed as a new epoch.
    std::string replay_error;
    CHECK(!apply_ratchet(sb, bob.pk, bob.sk, alice.pk, Bytes(64, 1), replay_error));
  }

  // Group sessions use a single shared key and do not ratchet.
  SecureBuffer group_key = CryptoEngine::random_bytes(32);
  Session ga;
  ga.sid = random_session_id();
  ga.group = true;
  ga.label = "team";
  ga.key_i2r = SecureBuffer(group_key.data(), group_key.size());
  ga.key_r2i = SecureBuffer(group_key.data(), group_key.size());
  ga.established = std::chrono::steady_clock::now();
  Session gb;
  gb.sid = ga.sid;
  gb.group = true;
  gb.key_i2r = SecureBuffer(group_key.data(), group_key.size());
  gb.key_r2i = SecureBuffer(group_key.data(), group_key.size());
  gb.established = ga.established;
  const std::uint64_t group_id = 4004;
  Bytes group_cipher = encrypt_chat_payload(alice, ga, payload_for(ga, alice, "team msg", 1, group_id));
  auto group_open = decrypt_chat_payload(bob, gb, group_cipher, group_id, error);
  CHECK(group_open.has_value());
  if (group_open) CHECK(group_open->text == "team msg");
  CHECK(!prepare_ratchet(ga, alice.pk, bob.pk).has_value());

  // Signed bytes are deterministic and bind all fields.
  Bytes s1 = chat_signing_bytes(ga.sid, alice.pk, 1, 2, 0, ChatKind::Chat, "x");
  Bytes s2 = chat_signing_bytes(ga.sid, alice.pk, 1, 2, 0, ChatKind::Chat, "x");
  Bytes s3 = chat_signing_bytes(ga.sid, alice.pk, 1, 2, 0, ChatKind::Chat, "y");
  CHECK(s1 == s2);
  CHECK(s1 != s3);
}

TEST_MAIN()
