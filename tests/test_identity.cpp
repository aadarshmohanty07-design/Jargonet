#include <algorithm>
#include <filesystem>
#include <string>

#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/identity.hpp"
#include "test_util.hpp"

using namespace jn;

void run() {
  auto dir = jntest::temp_dir("identity");
  CHECK(!IdentityManager::exists(dir));

  const std::string password = "correct horse battery staple";
  Identity created = IdentityManager::create(dir, "alice-test-name-42", password);
  CHECK(IdentityManager::exists(dir));
  CHECK(created.username == "alice-test-name-42");
  CHECK(created.fingerprint().size() == 32);
  CHECK(!is_zero(created.pk));
  CHECK(!is_zero(created.sign_pk));

  auto file = read_file(dir / IdentityManager::kIdentityFileName, 1 << 20);
  CHECK(file.has_value());
  // Neither the username nor raw keys may appear in the encrypted identity file.
  std::string bytes(reinterpret_cast<const char*>(file->data()), file->size());
  CHECK(bytes.find("alice-test-name-42") == std::string::npos);
  CHECK(bytes.find(std::string(reinterpret_cast<const char*>(created.pk.data()), created.pk.size())) ==
        std::string::npos);
  CHECK(bytes.find(std::string(reinterpret_cast<const char*>(created.sk.data()), created.sk.size())) ==
        std::string::npos);

  Identity unlocked = IdentityManager::unlock(dir, password);
  CHECK(unlocked.username == "alice-test-name-42");
  CHECK(unlocked.pk == created.pk);
  CHECK(unlocked.sign_pk == created.sign_pk);
  CHECK(unlocked.fingerprint() == created.fingerprint());
  CHECK(CryptoEngine::constant_time_equal(unlocked.sk.data(), created.sk.data(), 32));

  CHECK_THROWS(IdentityManager::unlock(dir, "incorrect password"));
  CHECK_THROWS(IdentityManager::create(dir, "bob", password));

  CHECK_THROWS(IdentityManager::validate_username(""));
  CHECK_THROWS(IdentityManager::validate_username("bad\nname"));
  CHECK_THROWS(IdentityManager::validate_username(" leading"));
  CHECK_THROWS(IdentityManager::validate_password("short"));
  IdentityManager::validate_password(password);

  // Corrupting the ciphertext must be detected.
  auto corrupt = *file;
  corrupt.back() ^= 0x01;
  std::string error;
  CHECK(write_file_atomic(dir / IdentityManager::kIdentityFileName, corrupt, true, error));
  CHECK_THROWS(IdentityManager::unlock(dir, password));

  IdentityManager::wipe(dir);
  CHECK(!IdentityManager::exists(dir));
  CHECK(!read_file(dir / IdentityManager::kIdentityFileName, 1 << 20).has_value());

  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
}

TEST_MAIN()
