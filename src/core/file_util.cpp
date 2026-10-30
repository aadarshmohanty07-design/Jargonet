#include "core/file_util.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>

#include "core/crypto.hpp"
#include "core/encoding.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#endif

namespace jn {
namespace fs = std::filesystem;

bool ensure_private_dir(const fs::path& dir, std::string& error) {
  std::error_code ec;
  if (!fs::exists(dir, ec)) {
    if (!fs::create_directories(dir, ec) || ec) {
      error = "cannot create directory " + dir.string() + ": " + ec.message();
      return false;
    }
  }
  if (!fs::is_directory(dir, ec)) {
    error = dir.string() + " is not a directory";
    return false;
  }
#ifndef _WIN32
  if (::chmod(dir.c_str(), 0700) != 0) {
    error = "cannot set private permissions on " + dir.string();
    return false;
  }
#endif
  return true;
}

bool write_file_atomic(const fs::path& path, const Bytes& data, bool private_permissions,
                       std::string& error) {
  fs::path dir = path.parent_path();
  if (!dir.empty()) {
    if (!ensure_private_dir(dir, error)) return false;
  }

  auto nonce = CryptoEngine::random_bytes(6);
  fs::path temp = path;
  temp += ".tmp." + hex_encode(nonce.data(), nonce.size());

  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      error = "cannot open " + temp.string() + " for writing";
      return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.flush();
    if (!out) {
      error = "failed writing " + temp.string();
      std::error_code ec;
      fs::remove(temp, ec);
      return false;
    }
  }

#ifndef _WIN32
  if (private_permissions) {
    ::chmod(temp.c_str(), 0600);
  }
#else
  (void)private_permissions;
#endif

#ifdef _WIN32
  if (!MoveFileExW(temp.wstring().c_str(), path.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    error = "cannot replace " + path.string();
    std::error_code ec;
    fs::remove(temp, ec);
    return false;
  }
#else
  std::error_code ec;
  fs::rename(temp, path, ec);
  if (ec) {
    error = "cannot replace " + path.string() + ": " + ec.message();
    fs::remove(temp, ec);
    return false;
  }
#endif
  return true;
}

std::optional<Bytes> read_file(const fs::path& path, std::size_t max_size) {
  std::error_code ec;
  if (!fs::exists(path, ec)) return std::nullopt;
  const auto size = fs::file_size(path, ec);
  if (ec || size > max_size) return std::nullopt;

  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  Bytes data(static_cast<std::size_t>(size));
  if (!data.empty()) {
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!in) return std::nullopt;
  }
  return data;
}

bool secure_remove(const fs::path& path) {
  std::error_code ec;
  if (!fs::exists(path, ec)) return true;

  const auto size = fs::file_size(path, ec);
  if (!ec && size > 0) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (file) {
      Bytes zeros(static_cast<std::size_t>(std::min<std::uintmax_t>(size, 1u << 20)), 0);
      std::uintmax_t left = size;
      while (left > 0) {
        const auto chunk = static_cast<std::streamsize>(
            std::min<std::uintmax_t>(left, zeros.size()));
        file.write(reinterpret_cast<const char*>(zeros.data()), chunk);
        if (!file) break;
        left -= static_cast<std::uintmax_t>(chunk);
      }
      file.flush();
    }
  }
  fs::remove(path, ec);
  return !ec;
}

fs::path default_data_dir() {
#ifdef _WIN32
  const char* appdata = std::getenv("APPDATA");
  if (appdata && *appdata) return fs::path(appdata) / "Jargonet";
  const char* profile = std::getenv("USERPROFILE");
  if (profile && *profile) return fs::path(profile) / "AppData" / "Roaming" / "Jargonet";
  return fs::temp_directory_path() / "Jargonet";
#elif defined(__APPLE__)
  const char* home = std::getenv("HOME");
  if (home) return fs::path(home) / "Library" / "Application Support" / "Jargonet";
  return fs::temp_directory_path() / "Jargonet";
#else
  const char* xdg = std::getenv("XDG_DATA_HOME");
  if (xdg && *xdg) return fs::path(xdg) / "jargonet";
  const char* home = std::getenv("HOME");
  if (home) return fs::path(home) / ".local" / "share" / "jargonet";
  return fs::temp_directory_path() / "jargonet";
#endif
}

}  // namespace jn
