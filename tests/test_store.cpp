#include <filesystem>
#include <string>

#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/packet.hpp"
#include "core/identity.hpp"
#include "storage/local_store.hpp"
#include "test_util.hpp"

using namespace jn;

void run() {
  auto dir = jntest::temp_dir("store");
  const std::string password = "correct horse battery staple";
  auto identity = jntest::make_identity("alice");

  SessionId sid = random_session_id();
  {
    LocalStore store(dir, password, true);
    CHECK(store.contacts().empty());
    store.upsert_contact(StoredContact{identity.pk, identity.sign_pk, "bob-the-peer-42"});

    StoredSession session;
    session.sid = sid;
    session.peer_pk = identity.pk;
    session.peer_sign_pk = identity.sign_pk;
    session.label = "bob";
    session.initiator = true;
    store.upsert_session(session);

    StoredMessage message;
    message.sid = sid;
    message.from_pk = identity.pk;
    message.from_name = "bob";
    message.outgoing = false;
    message.text = "the secret phrase is swordfish";
    message.seq = 1;
    store.append_message(message);
    for (int i = 2; i <= 5; ++i) {
      message.text = "message " + std::to_string(i);
      message.seq = static_cast<std::uint64_t>(i);
      store.append_message(message);
    }
    store.save();
  }

  auto raw = read_file(dir / LocalStore::kStoreFileName, 32 << 20);
  CHECK(raw.has_value());
  std::string raw_text(reinterpret_cast<const char*>(raw->data()), raw->size());
  CHECK(raw_text.find("swordfish") == std::string::npos);
  CHECK(raw_text.find("bob-the-peer-42") == std::string::npos);
  CHECK(raw_text.find(hex_encode(sid.data(), sid.size())) == std::string::npos);
  CHECK(raw_text.find("127.0.0.1") == std::string::npos);

  {
    LocalStore reopened(dir, password, true);
    CHECK(reopened.contacts().size() == 1);
    CHECK(reopened.contacts()[0].username == "bob-the-peer-42");
    CHECK(reopened.sessions().size() == 1);
    CHECK(reopened.sessions()[0].sid == sid);
    auto messages = reopened.messages(sid, 100);
    CHECK(messages.size() == 5);
    CHECK(messages.front().text == "the secret phrase is swordfish");
    CHECK(messages.back().seq == 5);
    auto limited = reopened.messages(sid, 2);
    CHECK(limited.size() == 2);
    CHECK(limited.back().seq == 5);
    CHECK_THROWS(LocalStore(dir, "wrong password", true));
  }

  LocalStore::wipe_files(dir);
  CHECK(!read_file(dir / LocalStore::kStoreFileName, 32 << 20).has_value());

  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
}

TEST_MAIN()
