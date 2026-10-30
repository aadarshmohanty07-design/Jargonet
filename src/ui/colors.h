#pragma once

namespace jn::ui::ansi {

inline constexpr const char* kReset = "\033[0m";
inline constexpr const char* kSys = "\033[90m";
inline constexpr const char* kPeer = "\033[36m";
inline constexpr const char* kSend = "\033[32m";
inline constexpr const char* kRecv = "\033[1;32m";
inline constexpr const char* kHop = "\033[33m";
inline constexpr const char* kErr = "\033[1;31m";
inline constexpr const char* kHexDim = "\033[2;37m";
inline constexpr const char* kRoute = "\033[35m";
inline constexpr const char* kBanner = "\033[36m";
inline constexpr const char* kBold = "\033[1m";

inline constexpr const char* kClearScreen = "\033[2J\033[H";

}  // namespace jn::ui::ansi
