#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "core/bytes.hpp"

namespace jn {

class CryptoError : public std::runtime_error {
 public:
  explicit CryptoError(const std::string& what) : std::runtime_error(what) {}
};

// Owns secret bytes and wipes them on destruction. Non-copyable; moves
// transfer ownership so the source no longer holds the bytes.
class SecureBuffer {
 public:
  SecureBuffer() = default;
  explicit SecureBuffer(std::size_t size);
  SecureBuffer(const std::uint8_t* data, std::size_t size);
  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  std::uint8_t* data() { return data_; }
  const std::uint8_t* data() const { return data_; }
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

  void resize(std::size_t new_size);
  void wipe();

  Bytes copy_bytes() const;

 private:
  std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
};

struct KeyPair {
  PublicKey pk{};
  SecureBuffer sk;
};

struct SignKeyPair {
  SignPublicKey pk{};
  SecureBuffer sk;
};

class CryptoEngine {
 public:
  static bool init();

  static KeyPair generate_box_keypair();
  static KeyPair generate_box_keypair_from_seed(const std::uint8_t* seed32);
  static PublicKey public_key_from_secret(const SecureBuffer& sk);

  static SignKeyPair generate_sign_keypair();

  static SecureBuffer random_bytes(std::size_t size);
  static Nonce random_nonce();
  static std::uint32_t random_u32(std::uint32_t bound);

  // Argon2id; salt must be kPwhashSaltBytes.
  static SecureBuffer pwhash(std::string_view password, const std::uint8_t* salt,
                             std::uint64_t opslimit, std::size_t memlimit,
                             std::size_t out_len);
  static void pwhash_default_params(std::uint64_t& opslimit, std::size_t& memlimit);
  static void pwhash_test_params(std::uint64_t& opslimit, std::size_t& memlimit);

  // Returns nonce || ciphertext (crypto_secretbox_easy).
  static Bytes secretbox_encrypt(const std::uint8_t* key, const std::uint8_t* plaintext,
                                 std::size_t len);
  static Bytes secretbox_decrypt(const std::uint8_t* key, const std::uint8_t* sealed,
                                 std::size_t len);

  // Anonymous sealed box (crypto_box_seal). Returns ciphertext only.
  static Bytes box_seal(const PublicKey& recipient, const std::uint8_t* plaintext,
                        std::size_t len);
  static Bytes box_seal_open(const PublicKey& recipient_pk, const SecureBuffer& recipient_sk,
                             const std::uint8_t* ciphertext, std::size_t len);

  // Authenticated crypto_box_easy. Returns nonce || ciphertext.
  static Bytes box_encrypt(const PublicKey& recipient, const SecureBuffer& sender_sk,
                           const std::uint8_t* plaintext, std::size_t len);
  static Bytes box_decrypt(const PublicKey& sender, const SecureBuffer& recipient_sk,
                           const std::uint8_t* sealed, std::size_t len);

  // crypto_kx direction helpers. Returns {rx, tx}.
  static std::pair<SecureBuffer, SecureBuffer> kx_client(const PublicKey& pk,
                                                        const SecureBuffer& sk,
                                                        const PublicKey& peer_pk);
  static std::pair<SecureBuffer, SecureBuffer> kx_server(const PublicKey& pk,
                                                        const SecureBuffer& sk,
                                                        const PublicKey& peer_pk);

  static SecureBuffer scalarmult(const SecureBuffer& sk, const PublicKey& peer_pk);

  static Bytes hash(const std::uint8_t* data, std::size_t len, std::size_t out_len = 32);
  static Bytes hash(const Bytes& data, std::size_t out_len = 32);

  static Bytes sign(const SecureBuffer& sign_sk, const std::uint8_t* data, std::size_t len);
  static bool verify(const SignPublicKey& sign_pk, const std::uint8_t* sig,
                     std::size_t sig_len, const std::uint8_t* data, std::size_t len);

  static bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                                  std::size_t len);
  static bool valid_public_key(const PublicKey& pk);
  static void wipe(void* data, std::size_t len);

  static SecureBuffer sealed_key_from_password(std::string_view password,
                                               const std::uint8_t* salt,
                                               std::uint64_t opslimit,
                                               std::size_t memlimit);
};

}  // namespace jn
