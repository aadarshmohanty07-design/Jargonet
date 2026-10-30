#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/bytes.hpp"

namespace jn::msg {

class Error : public std::runtime_error {
 public:
  explicit Error(const std::string& what) : std::runtime_error(what) {}
};

// Minimal MessagePack value used for control payloads, onions and storage.
// Map keys are strings and order is preserved, which keeps encodes
// deterministic for transcript hashing.
struct Value {
  enum class Type { Nil, Bool, Int, UInt, Double, Str, Bin, Array, Map };

  Type type = Type::Nil;
  bool boolean = false;
  std::int64_t integer = 0;
  std::uint64_t uinteger = 0;
  double real = 0.0;
  std::string str;
  Bytes bin;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> map;

  Value() = default;
  Value(std::nullptr_t) {}
  Value(bool v) : type(Type::Bool), boolean(v) {}
  Value(std::int64_t v) : type(Type::Int), integer(v) {}
  Value(std::uint64_t v) : type(Type::UInt), uinteger(v) {}
  Value(std::uint32_t v) : type(Type::UInt), uinteger(v) {}
  Value(int v) : type(Type::Int), integer(v) {}
  Value(double v) : type(Type::Double), real(v) {}
  Value(std::string v) : type(Type::Str), str(std::move(v)) {}
  Value(const char* v) : type(Type::Str), str(v) {}
  Value(Bytes v) : type(Type::Bin), bin(std::move(v)) {}
  Value(const PublicKey& pk) : type(Type::Bin), bin(pk.begin(), pk.end()) {}
  Value(const SessionId& sid) : type(Type::Bin), bin(sid.begin(), sid.end()) {}

  static Value make_array(std::initializer_list<Value> values);
  static Value make_map(std::initializer_list<std::pair<std::string, Value>> values);

  bool is_nil() const { return type == Type::Nil; }
  bool is_map() const { return type == Type::Map; }
  bool is_bin() const { return type == Type::Bin; }
  bool is_str() const { return type == Type::Str; }

  bool has(std::string_view key) const;
  const Value& at(std::string_view key) const;
  const Value* find(std::string_view key) const;

  const std::string& as_str() const;
  const Bytes& as_bin() const;
  std::uint64_t as_uint() const;
  std::int64_t as_int() const;
  bool as_bool() const;
  const std::vector<Value>& as_array() const;
  const std::vector<std::pair<std::string, Value>>& as_map() const;

  PublicKey as_public_key() const;
  SessionId as_session_id() const;
};

class Writer {
 public:
  Writer() = default;

  void nil();
  void boolean(bool value);
  void uint(std::uint64_t value);
  void integer(std::int64_t value);
  void real(double value);
  void str(std::string_view value);
  void bin(const std::uint8_t* data, std::size_t size);
  void bin(const Bytes& value);
  void array(std::size_t size);
  void map(std::size_t size);

  Bytes take() { return std::move(out_); }
  const Bytes& bytes() const { return out_; }

 private:
  Bytes out_;
};

Bytes encode(const Value& value);
Value decode(const std::uint8_t* data, std::size_t size);
Value decode(const Bytes& data);

constexpr std::size_t kMaxDecodeBytes = 1u << 20;
constexpr int kMaxDepth = 16;

}  // namespace jn::msg
