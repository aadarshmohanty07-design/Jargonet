#include "core/identity.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

#include "core/crypto.hpp"
#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/msgpack.hpp"

namespace jn {
namespace fs = std::filesystem;
namespace {

constexpr char kMagic[] = {'J', 'N', 'I', 'D', '1'};
constexpr std::size_t kMagicLen = sizeof(kMagic);
constexpr std::uint8_t kVersion = 1;

void put_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

Bytes encrypt_identity(const Identity& identity, const SecureBuffer& key) {
  msg::Writer writer;
  writer.map(7);
  writer.str("v");
  writer.uint(kVersion);
  writer.str("u");
  writer.str(identity.username);
  writer.str("pk");
  writer.bin(identity.pk.data(), identity.pk.size());
  writer.str("sk");
  writer.bin(identity.sk.data(), identity.sk.size());
  writer.str("spk");
  writer.bin(identity.sign_pk.data(), identity.sign_pk.size());
  writer.str("ssk");
  writer.bin(identity.sign_sk.data(), identity.sign_sk.size());
  writer.str("alg");
  writer.str("x25519-ed25519");

  Bytes plain = writer.take();
  Bytes sealed = CryptoEngine::secretbox_encrypt(key.data(), plain.data(), plain.size());
  CryptoEngine::wipe(plain.data(), plain.size());
  return sealed;
}

}  // namespace

std::string Identity::fingerprint() const { return jn::fingerprint(pk); }

std::string Identity::short_fingerprint() const {
  std::string fp = fingerprint();
  if (fp.size() <= 16) return fp;
  return fp.substr(0, 4) + "-" + fp.substr(4, 4) + "-" + fp.substr(8, 4) + "-" +
         fp.substr(12, 4);
}

void IdentityManager::validate_username(const std::string& username) {
  if (username.empty()) throw IdentityError("username cannot be empty");
  if (username.size() > 32) throw IdentityError("username must be at most 32 bytes");
  if (trim(username) != username) throw IdentityError("username cannot start or end with spaces");
  for (unsigned char c : username) {
    if (c < 0x20 || c == 0x7f) throw IdentityError("username contains control characters");
  }
}

void IdentityManager::validate_password(const std::string& password) {
  if (password.size() < kMinPasswordLength) {
    throw IdentityError("password must be at least 8 characters");
  }
  if (password.size() > kMaxPasswordLength) {
    throw IdentityError("password is too long");
  }
}

bool IdentityManager::exists(const fs::path& data_dir) {
  std::error_code ec;
  return fs::exists(data_dir / kIdentityFileName, ec);
}

Identity IdentityManager::create(const fs::path& data_dir, const std::string& username,
                                 const std::string& password) {
  CryptoEngine::init();
  validate_username(username);
  validate_password(password);

  if (exists(data_dir)) {
    throw IdentityError("an identity already exists in " + data_dir.string());
  }

  std::string error;
  if (!ensure_private_dir(data_dir, error)) throw IdentityError(error);

  auto box = CryptoEngine::generate_box_keypair();
  auto sign = CryptoEngine::generate_sign_keypair();

  Identity identity;
  identity.username = username;
  identity.pk = box.pk;
  identity.sk = std::move(box.sk);
  identity.sign_pk = sign.pk;
  identity.sign_sk = std::move(sign.sk);

  auto salt = CryptoEngine::random_bytes(kPwhashSaltBytes);
  std::uint64_t ops = 0;
  std::size_t mem = 0;
  CryptoEngine::pwhash_default_params(ops, mem);
  auto key = CryptoEngine::pwhash(password, salt.data(), ops, mem, 32);

  Bytes ciphertext = encrypt_identity(identity, key);
  Bytes file;
  file.insert(file.end(), std::begin(kMagic), std::end(kMagic));
  file.insert(file.end(), salt.data(), salt.data() + salt.size());
  put_u64(file, ops);
  put_u64(file, mem);
  file.insert(file.end(), ciphertext.begin(), ciphertext.end());

  if (!write_file_atomic(data_dir / kIdentityFileName, file, true, error)) {
    throw IdentityError(error);
  }
  return identity;
}

Identity IdentityManager::unlock(const fs::path& data_dir, const std::string& password) {
  CryptoEngine::init();
  auto file = read_file(data_dir / kIdentityFileName, 1 << 20);
  if (!file) throw IdentityError("no identity found in " + data_dir.string());

  const std::size_t min_header = kMagicLen + kPwhashSaltBytes + 8 + 8 + kNonceBytes +
                                 crypto_secretbox_MACBYTES;
  if (file->size() < min_header) throw IdentityError("identity file is truncated");
  if (std::memcmp(file->data(), kMagic, kMagicLen) != 0) {
    throw IdentityError("identity file has an unsupported format");
  }

  const std::uint8_t* p = file->data() + kMagicLen;
  const std::uint8_t* salt = p;
  p += kPwhashSaltBytes;
  std::uint64_t ops = get_u64(p);
  p += 8;
  std::uint64_t mem = get_u64(p);
  p += 8;
  const std::uint8_t* ciphertext = p;
  const std::size_t ciphertext_len = file->data() + file->size() - ciphertext;

  if (ops == 0 || ops > 100 || mem < 8192 || mem > (1ull << 32)) {
    throw IdentityError("identity file has invalid KDF parameters");
  }
  if (password.size() > kMaxPasswordLength) throw IdentityError("password is too long");

  auto key = CryptoEngine::pwhash(password, salt, ops, static_cast<std::size_t>(mem), 32);
  Bytes plain;
  try {
    plain = CryptoEngine::secretbox_decrypt(key.data(), ciphertext, ciphertext_len);
  } catch (const CryptoError&) {
    throw IdentityError("wrong password or corrupted identity file");
  }

  try {
    msg::Value root = msg::decode(plain);
    CryptoEngine::wipe(plain.data(), plain.size());
    if (root.at("v").as_uint() != kVersion) {
      throw IdentityError("unsupported identity version");
    }
    Identity identity;
    identity.username = root.at("u").as_str();
    identity.pk = root.at("pk").as_public_key();
    const Bytes& sk = root.at("sk").as_bin();
    const Bytes& spk = root.at("spk").as_bin();
    const Bytes& ssk = root.at("ssk").as_bin();
    if (sk.size() != kSecretKeyBytes || spk.size() != kSignPublicKeyBytes ||
        ssk.size() != kSignSecretKeyBytes) {
      throw IdentityError("identity key material has invalid lengths");
    }
    identity.sk = SecureBuffer(sk.data(), sk.size());
    identity.sign_pk = SignPublicKey{};
    std::copy(spk.begin(), spk.end(), identity.sign_pk.begin());
    identity.sign_sk = SecureBuffer(ssk.data(), ssk.size());

    PublicKey derived = CryptoEngine::public_key_from_secret(identity.sk);
    if (!CryptoEngine::constant_time_equal(derived.data(), identity.pk.data(),
                                          kPublicKeyBytes) ||
        is_zero(identity.sign_pk)) {
      throw IdentityError("identity key material failed validation");
    }
    validate_username(identity.username);
    return identity;
  } catch (const msg::Error& e) {
    throw IdentityError(std::string("corrupted identity file: ") + e.what());
  }
}

void IdentityManager::wipe(const fs::path& data_dir) {
  secure_remove(data_dir / kIdentityFileName);
  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(data_dir, ec)) {
    const auto name = entry.path().filename().string();
    if (name.rfind("identity.jnid.tmp.", 0) == 0) {
      secure_remove(entry.path());
    }
  }
}

}  // namespace jn
