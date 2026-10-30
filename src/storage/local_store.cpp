#include "storage/local_store.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/msgpack.hpp"

namespace jn {
namespace fs = std::filesystem;
namespace {

constexpr char kMagic[] = {'J', 'N', 'S', 'T', '1'};
constexpr std::size_t kMagicLen = sizeof(kMagic);
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t kMaxContacts = 1024;
constexpr std::size_t kMaxSessions = 512;
constexpr std::size_t kMaxMessagesTotal = 20000;
constexpr std::size_t kMaxMessagesPerSession = 5000;
constexpr std::size_t kMaxTextBytes = 2048;

void put_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

StoredContact contact_from_value(const msg::Value& v) {
  StoredContact c;
  c.pk = v.at("pk").as_public_key();
  const Bytes& spk = v.at("spk").as_bin();
  if (spk.size() != kSignPublicKeyBytes) throw StoreError("invalid signing key length");
  std::copy(spk.begin(), spk.end(), c.sign_pk.begin());
  c.username = v.at("n").as_str();
  if (c.username.size() > 64) throw StoreError("contact name too long");
  return c;
}

StoredSession session_from_value(const msg::Value& v) {
  StoredSession s;
  s.sid = v.at("sid").as_session_id();
  s.peer_pk = v.at("peer").as_public_key();
  const Bytes& spk = v.at("spk").as_bin();
  if (spk.size() != kSignPublicKeyBytes) throw StoreError("invalid session signing key");
  std::copy(spk.begin(), spk.end(), s.peer_sign_pk.begin());
  s.label = v.at("label").as_str();
  s.group = v.at("grp").as_bool();
  s.initiator = v.at("ini").as_bool();
  if (const msg::Value* members = v.find("members")) {
    for (const auto& item : members->as_array()) {
      s.members.push_back(contact_from_value(item));
    }
  }
  return s;
}

StoredMessage message_from_value(const msg::Value& v) {
  StoredMessage m;
  m.sid = v.at("sid").as_session_id();
  m.from_pk = v.at("from").as_public_key();
  m.from_name = v.at("name").as_str();
  m.outgoing = v.at("out").as_bool();
  m.text = v.at("text").as_str();
  m.seq = v.at("seq").as_uint();
  if (m.text.size() > kMaxTextBytes) throw StoreError("stored message too long");
  return m;
}

}  // namespace

LocalStore::LocalStore(const fs::path& data_dir, const std::string& password, bool fast_kdf)
    : dir_(data_dir), path_(data_dir / kStoreFileName) {
  CryptoEngine::init();
  std::string error;
  if (!ensure_private_dir(dir_, error)) throw StoreError(error);

  auto existing = read_file(path_, 64u << 20);
  if (existing) {
    const std::size_t min_header =
        kMagicLen + kPwhashSaltBytes + 8 + 8 + kNonceBytes + crypto_secretbox_MACBYTES;
    if (existing->size() < min_header) throw StoreError("local store is truncated");
    if (std::memcmp(existing->data(), kMagic, kMagicLen) != 0) {
      throw StoreError("local store has an unsupported format");
    }
    const std::uint8_t* p = existing->data() + kMagicLen;
    std::memcpy(salt_, p, kPwhashSaltBytes);
    p += kPwhashSaltBytes;
    ops_limit_ = get_u64(p);
    p += 8;
    const std::uint64_t mem = get_u64(p);
    p += 8;
    if (ops_limit_ == 0 || ops_limit_ > 100 || mem < 8192 || mem > (1ull << 32)) {
      throw StoreError("local store has invalid KDF parameters");
    }
    mem_limit_ = static_cast<std::size_t>(mem);
    key_ = CryptoEngine::pwhash(password, salt_, ops_limit_, mem_limit_, 32);
    Bytes plain;
    try {
      plain = CryptoEngine::secretbox_decrypt(key_.data(), p,
                                              existing->data() + existing->size() - p);
    } catch (const CryptoError&) {
      key_.wipe();
      throw StoreError("wrong password or corrupted local store");
    }
    try {
      msg::Value root = msg::decode(plain);
      CryptoEngine::wipe(plain.data(), plain.size());
      if (root.at("v").as_uint() != kVersion) throw StoreError("unsupported store version");
      for (const auto& item : root.at("contacts").as_array()) {
        if (contacts_.size() < kMaxContacts) contacts_.push_back(contact_from_value(item));
      }
      for (const auto& item : root.at("sessions").as_array()) {
        if (sessions_.size() < kMaxSessions) sessions_.push_back(session_from_value(item));
      }
      for (const auto& item : root.at("messages").as_array()) {
        if (messages_.size() < kMaxMessagesTotal) messages_.push_back(message_from_value(item));
      }
    } catch (const msg::Error& e) {
      key_.wipe();
      throw StoreError(std::string("corrupted local store: ") + e.what());
    } catch (const StoreError&) {
      key_.wipe();
      throw;
    }
  } else {
    auto salt = CryptoEngine::random_bytes(kPwhashSaltBytes);
    std::memcpy(salt_, salt.data(), kPwhashSaltBytes);
    if (fast_kdf) {
      CryptoEngine::pwhash_test_params(ops_limit_, mem_limit_);
    } else {
      CryptoEngine::pwhash_default_params(ops_limit_, mem_limit_);
    }
    key_ = CryptoEngine::pwhash(password, salt_, ops_limit_, mem_limit_, 32);
  }
}

LocalStore::~LocalStore() { key_.wipe(); }

Bytes LocalStore::serialise() const {
  msg::Writer writer;
  writer.map(4);
  writer.str("v");
  writer.uint(kVersion);

  writer.str("contacts");
  writer.array(contacts_.size());
  for (const auto& contact : contacts_) {
    writer.map(3);
    writer.str("pk");
    writer.bin(contact.pk.data(), contact.pk.size());
    writer.str("spk");
    writer.bin(contact.sign_pk.data(), contact.sign_pk.size());
    writer.str("n");
    writer.str(contact.username);
  }

  writer.str("sessions");
  writer.array(sessions_.size());
  for (const auto& s : sessions_) {
    writer.map(7);
    writer.str("sid");
    writer.bin(s.sid.data(), s.sid.size());
    writer.str("peer");
    writer.bin(s.peer_pk.data(), s.peer_pk.size());
    writer.str("spk");
    writer.bin(s.peer_sign_pk.data(), s.peer_sign_pk.size());
    writer.str("label");
    writer.str(s.label);
    writer.str("grp");
    writer.boolean(s.group);
    writer.str("ini");
    writer.boolean(s.initiator);
    writer.str("members");
    writer.array(s.members.size());
    for (const auto& member : s.members) {
      writer.map(3);
      writer.str("pk");
      writer.bin(member.pk.data(), member.pk.size());
      writer.str("spk");
      writer.bin(member.sign_pk.data(), member.sign_pk.size());
      writer.str("n");
      writer.str(member.username);
    }
  }

  writer.str("messages");
  writer.array(messages_.size());
  for (const auto& m : messages_) {
    writer.map(6);
    writer.str("sid");
    writer.bin(m.sid.data(), m.sid.size());
    writer.str("from");
    writer.bin(m.from_pk.data(), m.from_pk.size());
    writer.str("name");
    writer.str(m.from_name);
    writer.str("out");
    writer.boolean(m.outgoing);
    writer.str("text");
    writer.str(m.text);
    writer.str("seq");
    writer.uint(m.seq);
  }
  return writer.take();
}

void LocalStore::save() {
  Bytes plain = serialise();
  Bytes sealed = CryptoEngine::secretbox_encrypt(key_.data(), plain.data(), plain.size());
  CryptoEngine::wipe(plain.data(), plain.size());

  Bytes file;
  file.insert(file.end(), std::begin(kMagic), std::end(kMagic));
  file.insert(file.end(), salt_, salt_ + kPwhashSaltBytes);
  put_u64(file, ops_limit_);
  put_u64(file, static_cast<std::uint64_t>(mem_limit_));
  file.insert(file.end(), sealed.begin(), sealed.end());

  std::string error;
  if (!write_file_atomic(path_, file, true, error)) throw StoreError(error);
  }

void LocalStore::upsert_contact(const StoredContact& contact) {
  if (contact.pk == kZeroPublicKey || contact.username.empty()) {
    throw StoreError("invalid contact");
  }
  for (auto& existing : contacts_) {
    if (existing.pk == contact.pk) {
      existing = contact;
      save();
      return;
    }
  }
  if (contacts_.size() >= kMaxContacts) throw StoreError("contact limit reached");
  contacts_.push_back(contact);
  save();
}

void LocalStore::upsert_session(const StoredSession& session) {
  for (auto& existing : sessions_) {
    if (existing.sid == session.sid) {
      existing = session;
      save();
      return;
    }
  }
  if (sessions_.size() >= kMaxSessions) throw StoreError("session limit reached");
  sessions_.push_back(session);
  save();
}

void LocalStore::append_message(const StoredMessage& message) {
  if (message.text.size() > kMaxTextBytes) throw StoreError("message too long");
  messages_.push_back(message);

  std::size_t per_session = 0;
  for (const auto& m : messages_) {
    if (m.sid == message.sid) ++per_session;
  }
  while (per_session > kMaxMessagesPerSession) {
    auto it = std::find_if(messages_.begin(), messages_.end(),
                           [&](const StoredMessage& m) { return m.sid == message.sid; });
    if (it == messages_.end()) break;
    messages_.erase(it);
    --per_session;
  }
  while (messages_.size() > kMaxMessagesTotal) messages_.erase(messages_.begin());
  save();
}

std::vector<StoredMessage> LocalStore::messages(const SessionId& sid, std::size_t limit) const {
  std::vector<StoredMessage> out;
  for (const auto& m : messages_) {
    if (m.sid == sid) out.push_back(m);
  }
  if (out.size() > limit) out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(limit));
  return out;
}

std::optional<StoredContact> LocalStore::find_contact(const PublicKey& pk) const {
  for (const auto& contact : contacts_) {
    if (contact.pk == pk) return contact;
  }
  return std::nullopt;
}

std::optional<StoredSession> LocalStore::find_session(const SessionId& sid) const {
  for (const auto& session : sessions_) {
    if (session.sid == sid) return session;
  }
  return std::nullopt;
}

void LocalStore::wipe_files(const fs::path& data_dir) {
  secure_remove(data_dir / kStoreFileName);
  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(data_dir, ec)) {
    const auto name = entry.path().filename().string();
    if (name.rfind(std::string(kStoreFileName) + ".tmp.", 0) == 0) {
      secure_remove(entry.path());
    }
  }
}

}  // namespace jn
