#pragma once

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>

#include "core/crypto.hpp"
#include "core/identity.hpp"

namespace jntest {

inline int& failures() {
  static int value = 0;
  return value;
}

inline void fail(const char* file, int line, const std::string& expression) {
  std::cerr << file << ":" << line << "  FAILED: " << expression << "\n";
  ++failures();
}

#define CHECK(condition)                                              \
  do {                                                                \
    if (!(condition)) jntest::fail(__FILE__, __LINE__, #condition);   \
  } while (false)

#define CHECK_THROWS(expression)                                      \
  do {                                                                \
    bool threw = false;                                               \
    try {                                                             \
      (void)(expression);                                             \
    } catch (...) {                                                   \
      threw = true;                                                   \
    }                                                                 \
    if (!threw) jntest::fail(__FILE__, __LINE__, "expected throw: " #expression); \
  } while (false)

inline std::filesystem::path temp_dir(const std::string& tag) {
  static int counter = 0;
  auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
  auto dir = std::filesystem::temp_directory_path() /
             ("jargonet-test-" + tag + "-" + std::to_string(stamp) + "-" +
              std::to_string(counter++));
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return dir;
}

inline jn::Identity make_identity(const std::string& name) {
  jn::Identity identity;
  identity.username = name;
  auto box = jn::CryptoEngine::generate_box_keypair();
  identity.pk = box.pk;
  identity.sk = std::move(box.sk);
  auto sign = jn::CryptoEngine::generate_sign_keypair();
  identity.sign_pk = sign.pk;
  identity.sign_sk = std::move(sign.sk);
  return identity;
}

#define TEST_MAIN()                                                          \
  int main() {                                                               \
    try {                                                                    \
      jn::CryptoEngine::init();                                             \
      run();                                                                 \
    } catch (const std::exception& e) {                                      \
      std::cerr << "EXCEPTION: " << e.what() << "\n";                       \
      return 1;                                                              \
    }                                                                        \
    if (jntest::failures() != 0) {                                           \
      std::cerr << jntest::failures() << " check(s) failed\n";              \
      return 1;                                                              \
    }                                                                        \
    std::cout << "ok\n";                                                     \
    return 0;                                                                \
  }

}  // namespace jntest
