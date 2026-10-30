#include "core/crypto.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace jn {
namespace {

void ensure_init() {
  static const bool ready = [] {
    if (sodium_init() < 0) {
      throw CryptoError("libsodium initialization failed");
    }
    return true;
  }();
  (void)ready;
}

std::size_t secretbox_sealed_size(std::size_t len) { return kNonceBytes + crypto_secretbox_MACBYTES + len; }

}  // namespace

SecureBuffer::SecureBuffer(std::size_t size) : size_(size) {
  if (size > 0) {
    data_ = static_cast<std::uint8_t*>(sodium_malloc(size));
    if (!data_) throw std::bad_alloc();
  }
}

SecureBuffer::SecureBuffer(const std::uint8_t* data, std::size_t size) : SecureBuffer(size) {
  if (size > 0 && data) std::memcpy(data_, data, size);
}

SecureBuffer::~SecureBuffer() { wipe(); }

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    wipe();
    data_ = other.data_;
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

void SecureBuffer::resize(std::size_t new_size) {
  if (new_size == size_) return;
  wipe();
  if (new_size > 0) {
    data_ = static_cast<std::uint8_t*>(sodium_malloc(new_size));
    if (!data_) throw std::bad_alloc();
  }
  size_ = new_size;
}

void SecureBuffer::wipe() {
  if (data_) {
    sodium_memzero(data_, size_);
    sodium_free(data_);
  }
  data_ = nullptr;
  size_ = 0;
}

Bytes SecureBuffer::copy_bytes() const {
  if (!data_ || size_ == 0) return {};
  return Bytes(data_, data_ + size_);
}

bool CryptoEngine::init() {
  ensure_init();
  return true;
}

KeyPair CryptoEngine::generate_box_keypair() {
  ensure_init();
  KeyPair kp;
  kp.sk.resize(kSecretKeyBytes);
  if (crypto_box_keypair(kp.pk.data(), kp.sk.data()) != 0) {
    throw CryptoError("crypto_box_keypair failed");
  }
  return kp;
}

KeyPair CryptoEngine::generate_box_keypair_from_seed(const std::uint8_t* seed32) {
  ensure_init();
  KeyPair kp;
  kp.sk.resize(kSecretKeyBytes);
  if (crypto_box_seed_keypair(kp.pk.data(), kp.sk.data(), seed32) != 0) {
    throw CryptoError("crypto_box_seed_keypair failed");
  }
  return kp;
}

PublicKey CryptoEngine::public_key_from_secret(const SecureBuffer& sk) {
  ensure_init();
  if (sk.size() != kSecretKeyBytes) throw CryptoError("invalid secret key length");
  PublicKey pk{};
  if (crypto_scalarmult_base(pk.data(), sk.data()) != 0) {
    throw CryptoError("crypto_scalarmult_base failed");
  }
  return pk;
}

SignKeyPair CryptoEngine::generate_sign_keypair() {
  ensure_init();
  SignKeyPair kp;
  kp.sk.resize(kSignSecretKeyBytes);
  if (crypto_sign_keypair(kp.pk.data(), kp.sk.data()) != 0) {
    throw CryptoError("crypto_sign_keypair failed");
  }
  return kp;
}

SecureBuffer CryptoEngine::random_bytes(std::size_t size) {
  ensure_init();
  SecureBuffer buf(size);
  if (size > 0) randombytes_buf(buf.data(), size);
  return buf;
}

Nonce CryptoEngine::random_nonce() {
  ensure_init();
  Nonce nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  return nonce;
}

std::uint32_t CryptoEngine::random_u32(std::uint32_t bound) {
  ensure_init();
  if (bound == 0) return 0;
  return randombytes_uniform(bound);
}

SecureBuffer CryptoEngine::pwhash(std::string_view password, const std::uint8_t* salt,
                                  std::uint64_t opslimit, std::size_t memlimit,
                                  std::size_t out_len) {
  ensure_init();
  SecureBuffer out(out_len);
  if (crypto_pwhash(out.data(), out_len, password.data(), password.size(), salt,
                    opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw CryptoError("crypto_pwhash failed (out of memory?)");
  }
  return out;
}

void CryptoEngine::pwhash_default_params(std::uint64_t& opslimit, std::size_t& memlimit) {
  opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
}

void CryptoEngine::pwhash_test_params(std::uint64_t& opslimit, std::size_t& memlimit) {
  opslimit = crypto_pwhash_OPSLIMIT_MIN;
  memlimit = crypto_pwhash_MEMLIMIT_MIN;
}

Bytes CryptoEngine::secretbox_encrypt(const std::uint8_t* key, const std::uint8_t* plaintext,
                                      std::size_t len) {
  ensure_init();
  if (!key) throw CryptoError("missing key");
  Nonce nonce = random_nonce();
  Bytes out(secretbox_sealed_size(len));
  std::memcpy(out.data(), nonce.data(), nonce.size());
  if (crypto_secretbox_easy(out.data() + kNonceBytes, plaintext ? plaintext : reinterpret_cast<const std::uint8_t*>(""),
                            len, nonce.data(), key) != 0) {
    throw CryptoError("crypto_secretbox_easy failed");
  }
  return out;
}

Bytes CryptoEngine::secretbox_decrypt(const std::uint8_t* key, const std::uint8_t* sealed,
                                      std::size_t len) {
  ensure_init();
  if (!key || !sealed || len < kNonceBytes + crypto_secretbox_MACBYTES) {
    throw CryptoError("secretbox ciphertext too short");
  }
  Bytes out(len - kNonceBytes - crypto_secretbox_MACBYTES);
  if (crypto_secretbox_open_easy(out.data(), sealed + kNonceBytes,
                                 len - kNonceBytes, sealed, key) != 0) {
    throw CryptoError("secretbox authentication failed");
  }
  return out;
}

Bytes CryptoEngine::box_seal(const PublicKey& recipient, const std::uint8_t* plaintext,
                             std::size_t len) {
  ensure_init();
  if (!valid_public_key(recipient)) throw CryptoError("invalid recipient public key");
  Bytes out(len + crypto_box_SEALBYTES);
  if (crypto_box_seal(out.data(), plaintext ? plaintext : reinterpret_cast<const std::uint8_t*>(""),
                      len, recipient.data()) != 0) {
    throw CryptoError("crypto_box_seal failed");
  }
  return out;
}

Bytes CryptoEngine::box_seal_open(const PublicKey& recipient_pk, const SecureBuffer& recipient_sk,
                                  const std::uint8_t* ciphertext, std::size_t len) {
  ensure_init();
  if (recipient_sk.size() != kSecretKeyBytes || !ciphertext ||
      len < crypto_box_SEALBYTES) {
    throw CryptoError("sealed box ciphertext too short");
  }
  Bytes out(len - crypto_box_SEALBYTES);
  if (crypto_box_seal_open(out.data(), ciphertext, len, recipient_pk.data(),
                           recipient_sk.data()) != 0) {
    throw CryptoError("sealed box authentication failed");
  }
  return out;
}

Bytes CryptoEngine::box_encrypt(const PublicKey& recipient, const SecureBuffer& sender_sk,
                                const std::uint8_t* plaintext, std::size_t len) {
  ensure_init();
  if (!valid_public_key(recipient) || sender_sk.size() != kSecretKeyBytes) {
    throw CryptoError("invalid box key");
  }
  Nonce nonce = random_nonce();
  Bytes out(kNonceBytes + crypto_box_MACBYTES + len);
  std::memcpy(out.data(), nonce.data(), nonce.size());
  if (crypto_box_easy(out.data() + kNonceBytes, plaintext ? plaintext : reinterpret_cast<const std::uint8_t*>(""),
                      len, nonce.data(), recipient.data(), sender_sk.data()) != 0) {
    throw CryptoError("crypto_box_easy failed");
  }
  return out;
}

Bytes CryptoEngine::box_decrypt(const PublicKey& sender, const SecureBuffer& recipient_sk,
                                const std::uint8_t* sealed, std::size_t len) {
  ensure_init();
  if (!valid_public_key(sender) || recipient_sk.size() != kSecretKeyBytes || !sealed ||
      len < kNonceBytes + crypto_box_MACBYTES) {
    throw CryptoError("box ciphertext too short");
  }
  Bytes out(len - kNonceBytes - crypto_box_MACBYTES);
  if (crypto_box_open_easy(out.data(), sealed + kNonceBytes, len - kNonceBytes, sealed,
                           sender.data(), recipient_sk.data()) != 0) {
    throw CryptoError("crypto_box authentication failed");
  }
  return out;
}

std::pair<SecureBuffer, SecureBuffer> CryptoEngine::kx_client(const PublicKey& pk,
                                                              const SecureBuffer& sk,
                                                              const PublicKey& peer_pk) {
  ensure_init();
  if (sk.size() != kSecretKeyBytes || !valid_public_key(pk) || !valid_public_key(peer_pk)) {
    throw CryptoError("invalid kx keys");
  }
  SecureBuffer rx(crypto_kx_SESSIONKEYBYTES);
  SecureBuffer tx(crypto_kx_SESSIONKEYBYTES);
  if (crypto_kx_client_session_keys(rx.data(), tx.data(), pk.data(), sk.data(),
                                    peer_pk.data()) != 0) {
    throw CryptoError("crypto_kx_client_session_keys failed");
  }
  return {std::move(rx), std::move(tx)};
}

std::pair<SecureBuffer, SecureBuffer> CryptoEngine::kx_server(const PublicKey& pk,
                                                              const SecureBuffer& sk,
                                                              const PublicKey& peer_pk) {
  ensure_init();
  if (sk.size() != kSecretKeyBytes || !valid_public_key(pk) || !valid_public_key(peer_pk)) {
    throw CryptoError("invalid kx keys");
  }
  SecureBuffer rx(crypto_kx_SESSIONKEYBYTES);
  SecureBuffer tx(crypto_kx_SESSIONKEYBYTES);
  if (crypto_kx_server_session_keys(rx.data(), tx.data(), pk.data(), sk.data(),
                                    peer_pk.data()) != 0) {
    throw CryptoError("crypto_kx_server_session_keys failed");
  }
  return {std::move(rx), std::move(tx)};
}

SecureBuffer CryptoEngine::scalarmult(const SecureBuffer& sk, const PublicKey& peer_pk) {
  ensure_init();
  if (sk.size() != kSecretKeyBytes || !valid_public_key(peer_pk)) {
    throw CryptoError("invalid scalarmult key");
  }
  SecureBuffer out(crypto_scalarmult_BYTES);
  if (crypto_scalarmult(out.data(), sk.data(), peer_pk.data()) != 0) {
    throw CryptoError("crypto_scalarmult failed");
  }
  return out;
}

Bytes CryptoEngine::hash(const std::uint8_t* data, std::size_t len, std::size_t out_len) {
  ensure_init();
  if (out_len < crypto_generichash_BYTES_MIN || out_len > crypto_generichash_BYTES_MAX) {
    throw CryptoError("invalid hash length");
  }
  Bytes out(out_len);
  if (crypto_generichash(out.data(), out_len, data, len, nullptr, 0) != 0) {
    throw CryptoError("crypto_generichash failed");
  }
  return out;
}

Bytes CryptoEngine::hash(const Bytes& data, std::size_t out_len) {
  return hash(data.data(), data.size(), out_len);
}

Bytes CryptoEngine::sign(const SecureBuffer& sign_sk, const std::uint8_t* data,
                         std::size_t len) {
  ensure_init();
  if (sign_sk.size() != kSignSecretKeyBytes) throw CryptoError("invalid signing key");
  Bytes sig(crypto_sign_BYTES);
  unsigned long long sig_len = 0;
  if (crypto_sign_detached(sig.data(), &sig_len, data, len, sign_sk.data()) != 0) {
    throw CryptoError("crypto_sign_detached failed");
  }
  return sig;
}

bool CryptoEngine::verify(const SignPublicKey& sign_pk, const std::uint8_t* sig,
                          std::size_t sig_len, const std::uint8_t* data, std::size_t len) {
  ensure_init();
  if (sig_len != crypto_sign_BYTES) return false;
  return crypto_sign_verify_detached(sig, data, len, sign_pk.data()) == 0;
}

bool CryptoEngine::constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                                       std::size_t len) {
  ensure_init();
  return sodium_memcmp(a, b, len) == 0;
}

bool CryptoEngine::valid_public_key(const PublicKey& pk) {
  ensure_init();
  if (is_zero(pk)) return false;
  // X25519 accepts almost any 32-byte string, but low-order points produce a
  // zero shared secret. Probe the point and reject those.
  static constexpr std::array<std::uint8_t, kPublicKeyBytes> kProbe = {
      0x5a, 0x1f, 0x93, 0x2c, 0x77, 0xe1, 0x04, 0xb8, 0x6d, 0x33, 0xaa, 0x91,
      0x0e, 0x5c, 0xf2, 0x48, 0x17, 0x9b, 0xc5, 0x2e, 0x68, 0xd0, 0x3b, 0xa7,
      0x54, 0xee, 0x0a, 0x86, 0x71, 0xc9, 0x25, 0x4f};
  std::array<std::uint8_t, 32> probe{};
  const bool ok = crypto_scalarmult(probe.data(), kProbe.data(), pk.data()) == 0;
  sodium_memzero(probe.data(), probe.size());
  return ok;
}

void CryptoEngine::wipe(void* data, std::size_t len) {
  if (data && len) sodium_memzero(data, len);
}

SecureBuffer CryptoEngine::sealed_key_from_password(std::string_view password,
                                                    const std::uint8_t* salt,
                                                    std::uint64_t opslimit,
                                                    std::size_t memlimit) {
  return pwhash(password, salt, opslimit, memlimit, 32);
}

}  // namespace jn
