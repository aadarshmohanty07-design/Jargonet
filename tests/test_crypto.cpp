#include <cstring>
#include <string>
#include <vector>

#include "core/crypto.hpp"
#include "core/encoding.hpp"
#include "test_util.hpp"

using namespace jn;

void run() {
  // Box keypairs and public-key derivation.
  auto alice = CryptoEngine::generate_box_keypair();
  auto bob = CryptoEngine::generate_box_keypair();
  CHECK(CryptoEngine::valid_public_key(alice.pk));
  CHECK(CryptoEngine::valid_public_key(bob.pk));
  CHECK(alice.pk != bob.pk);
  PublicKey derived = CryptoEngine::public_key_from_secret(alice.sk);
  CHECK(derived == alice.pk);
  CHECK(is_zero(PublicKey{}));
  CHECK(!CryptoEngine::valid_public_key(kZeroPublicKey));
  PublicKey low_order{};
  low_order[0] = 1;
  CHECK(!CryptoEngine::valid_public_key(low_order));

  // Secretbox.
  auto key = CryptoEngine::random_bytes(32);
  std::string message = "hello secrecy";
  Bytes sealed = CryptoEngine::secretbox_encrypt(
      key.data(), reinterpret_cast<const std::uint8_t*>(message.data()), message.size());
  CHECK(sealed.size() == kNonceBytes + 16 + message.size());
  Bytes plain = CryptoEngine::secretbox_decrypt(key.data(), sealed.data(), sealed.size());
  CHECK(std::string(plain.begin(), plain.end()) == message);

  Bytes tampered = sealed;
  tampered.back() ^= 0x01;
  CHECK_THROWS(CryptoEngine::secretbox_decrypt(key.data(), tampered.data(), tampered.size()));
  auto other_key = CryptoEngine::random_bytes(32);
  CHECK_THROWS(CryptoEngine::secretbox_decrypt(other_key.data(), sealed.data(), sealed.size()));
  CHECK_THROWS(CryptoEngine::secretbox_decrypt(key.data(), sealed.data(), 10));

  // Authenticated box.
  Bytes boxed = CryptoEngine::box_encrypt(bob.pk, alice.sk,
                                          reinterpret_cast<const std::uint8_t*>(message.data()),
                                          message.size());
  Bytes opened = CryptoEngine::box_decrypt(alice.pk, bob.sk, boxed.data(), boxed.size());
  CHECK(std::string(opened.begin(), opened.end()) == message);
  CHECK_THROWS(CryptoEngine::box_decrypt(bob.pk, bob.sk, boxed.data(), boxed.size()));
  Bytes box_tampered = boxed;
  box_tampered[box_tampered.size() - 1] ^= 0x80;
  CHECK_THROWS(CryptoEngine::box_decrypt(alice.pk, bob.sk, box_tampered.data(),
                                         box_tampered.size()));

  // Sealed box.
  Bytes sealed_box = CryptoEngine::box_seal(bob.pk,
                                            reinterpret_cast<const std::uint8_t*>(message.data()),
                                            message.size());
  Bytes unsealed = CryptoEngine::box_seal_open(bob.pk, bob.sk, sealed_box.data(), sealed_box.size());
  CHECK(std::string(unsealed.begin(), unsealed.end()) == message);
  CHECK_THROWS(CryptoEngine::box_seal_open(alice.pk, alice.sk, sealed_box.data(),
                                           sealed_box.size()));

  // crypto_kx agreement.
  auto client = CryptoEngine::kx_client(alice.pk, alice.sk, bob.pk);
  auto server = CryptoEngine::kx_server(bob.pk, bob.sk, alice.pk);
  CHECK(CryptoEngine::constant_time_equal(client.second.data(), server.first.data(), 32));
  CHECK(CryptoEngine::constant_time_equal(client.first.data(), server.second.data(), 32));

  // X25519 shared secret symmetry.
  auto alice_eph = CryptoEngine::generate_box_keypair();
  auto bob_eph = CryptoEngine::generate_box_keypair();
  auto shared_a = CryptoEngine::scalarmult(alice_eph.sk, bob_eph.pk);
  auto shared_b = CryptoEngine::scalarmult(bob_eph.sk, alice_eph.pk);
  CHECK(CryptoEngine::constant_time_equal(shared_a.data(), shared_b.data(), 32));

  // Signatures.
  auto signer = CryptoEngine::generate_sign_keypair();
  Bytes signature = CryptoEngine::sign(signer.sk,
                                       reinterpret_cast<const std::uint8_t*>(message.data()),
                                       message.size());
  CHECK(CryptoEngine::verify(signer.pk, signature.data(), signature.size(),
                             reinterpret_cast<const std::uint8_t*>(message.data()),
                             message.size()));
  Bytes signed_tamper = signature;
  signed_tamper[0] ^= 1;
  CHECK(!CryptoEngine::verify(signer.pk, signed_tamper.data(), signed_tamper.size(),
                              reinterpret_cast<const std::uint8_t*>(message.data()),
                              message.size()));
  CHECK(!CryptoEngine::verify(signer.pk, signature.data(), signature.size(),
                              reinterpret_cast<const std::uint8_t*>("different"),
                              std::strlen("different")));

  // pwhash is deterministic for a fixed salt and differs across salts.
  std::uint64_t ops = 0;
  std::size_t mem = 0;
  CryptoEngine::pwhash_test_params(ops, mem);
  std::uint8_t salt[kPwhashSaltBytes];
  std::memset(salt, 0x42, sizeof(salt));
  auto k1 = CryptoEngine::pwhash("correct horse battery staple", salt, ops, mem, 32);
  auto k2 = CryptoEngine::pwhash("correct horse battery staple", salt, ops, mem, 32);
  CHECK(CryptoEngine::constant_time_equal(k1.data(), k2.data(), 32));
  salt[0] ^= 1;
  auto k3 = CryptoEngine::pwhash("correct horse battery staple", salt, ops, mem, 32);
  CHECK(!CryptoEngine::constant_time_equal(k1.data(), k3.data(), 32));
  auto k4 = CryptoEngine::pwhash("wrong password", salt, ops, mem, 32);
  CHECK(!CryptoEngine::constant_time_equal(k3.data(), k4.data(), 32));

  // Fingerprints.
  CHECK(fingerprint(alice.pk) == fingerprint(alice.pk));
  CHECK(fingerprint(alice.pk) != fingerprint(bob.pk));
  CHECK(fingerprint(alice.pk).size() == 32);
  CHECK(pretty_fingerprint(alice.pk).size() == 32 + 7);

  // Randomness.
  auto r1 = CryptoEngine::random_bytes(32);
  auto r2 = CryptoEngine::random_bytes(32);
  CHECK(!CryptoEngine::constant_time_equal(r1.data(), r2.data(), 32));
  CHECK(CryptoEngine::random_u32(1) == 0);

  // Encodings.
  Bytes data{0x00, 0x01, 0xfe, 0xff, 0x10, 0x20, 0x30};
  CHECK(hex_decode(hex_encode(data)).value() == data);
  CHECK(base64url_decode(base64url_encode(data)).value() == data);
  CHECK(!hex_decode("abc").has_value());
  CHECK(!base64url_decode("!!!!").has_value());
}

TEST_MAIN()
