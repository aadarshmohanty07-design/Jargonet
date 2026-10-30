#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "core/bytes.hpp"

namespace jn {

bool ensure_private_dir(const std::filesystem::path& dir, std::string& error);

// Writes via a temporary file and atomically replaces the destination.
bool write_file_atomic(const std::filesystem::path& path, const Bytes& data,
                       bool private_permissions, std::string& error);

std::optional<Bytes> read_file(const std::filesystem::path& path, std::size_t max_size);

// Best-effort secure delete: overwrite the file before unlinking. Flash
// storage and filesystem journaling can retain old blocks; see SECURITY.md.
bool secure_remove(const std::filesystem::path& path);

std::filesystem::path default_data_dir();

}  // namespace jn
