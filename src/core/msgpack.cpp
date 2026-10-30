#include "core/msgpack.hpp"

#include <cstring>
#include <limits>

namespace jn::msg {
namespace {

void append_u16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

void append_u32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 24));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

void append_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

class Reader {
 public:
  Reader(const std::uint8_t* data, std::size_t size) : begin_(data), cursor_(data), end_(data + size) {}

  std::size_t remaining() const { return static_cast<std::size_t>(end_ - cursor_); }

  std::uint8_t u8() {
    require(1);
    return *cursor_++;
  }

  std::uint16_t u16() {
    require(2);
    std::uint16_t v = static_cast<std::uint16_t>((cursor_[0] << 8) | cursor_[1]);
    cursor_ += 2;
    return v;
  }

  std::uint32_t u32() {
    require(4);
    std::uint32_t v = (static_cast<std::uint32_t>(cursor_[0]) << 24) |
                      (static_cast<std::uint32_t>(cursor_[1]) << 16) |
                      (static_cast<std::uint32_t>(cursor_[2]) << 8) |
                      static_cast<std::uint32_t>(cursor_[3]);
    cursor_ += 4;
    return v;
  }

  std::uint64_t u64() {
    require(8);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | cursor_[i];
    cursor_ += 8;
    return v;
  }

  const std::uint8_t* raw(std::size_t n) {
    require(n);
    const std::uint8_t* p = cursor_;
    cursor_ += n;
    return p;
  }

  void skip(std::size_t n) { (void)raw(n); }

  Value read(int depth) {
    if (depth > kMaxDepth) throw Error("msgpack nesting too deep");
    const std::uint8_t marker = u8();

    if (marker <= 0x7f) return Value(static_cast<std::uint64_t>(marker));
    if (marker >= 0xe0) return Value(static_cast<std::int64_t>(static_cast<std::int8_t>(marker)));

    if ((marker & 0xf0) == 0x80) {
      const std::size_t n = marker & 0x0f;
      Value v;
      v.type = Value::Type::Map;
      v.map.reserve(n);
      for (std::size_t i = 0; i < n; ++i) {
        Value key = read(depth + 1);
        if (key.type != Value::Type::Str) throw Error("msgpack map key must be a string");
        Value val = read(depth + 1);
        v.map.emplace_back(std::move(key.str), std::move(val));
      }
      return v;
    }
    if ((marker & 0xf0) == 0x90) {
      const std::size_t n = marker & 0x0f;
      Value v;
      v.type = Value::Type::Array;
      v.array.reserve(n);
      for (std::size_t i = 0; i < n; ++i) v.array.push_back(read(depth + 1));
      return v;
    }
    if ((marker & 0xe0) == 0xa0) {
      const std::size_t n = marker & 0x1f;
      const std::uint8_t* p = raw(n);
      Value v;
      v.type = Value::Type::Str;
      v.str.assign(reinterpret_cast<const char*>(p), n);
      return v;
    }

    switch (marker) {
      case 0xc0:
        return Value();
      case 0xc2:
        return Value(false);
      case 0xc3:
        return Value(true);
      case 0xc4: {
        const std::size_t n = u8();
        Value v;
        v.type = Value::Type::Bin;
        const std::uint8_t* p = raw(n);
        v.bin.assign(p, p + n);
        return v;
      }
      case 0xc5: {
        const std::size_t n = u16();
        Value v;
        v.type = Value::Type::Bin;
        const std::uint8_t* p = raw(n);
        v.bin.assign(p, p + n);
        return v;
      }
      case 0xc6: {
        const std::size_t n = u32();
        if (n > kMaxDecodeBytes) throw Error("msgpack binary too large");
        Value v;
        v.type = Value::Type::Bin;
        const std::uint8_t* p = raw(n);
        v.bin.assign(p, p + n);
        return v;
      }
      case 0xca: {
        const std::uint32_t bits = u32();
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        return Value(static_cast<double>(f));
      }
      case 0xcb: {
        const std::uint64_t bits = u64();
        double d;
        std::memcpy(&d, &bits, sizeof(d));
        return Value(d);
      }
      case 0xcc:
        return Value(static_cast<std::uint64_t>(u8()));
      case 0xcd:
        return Value(static_cast<std::uint64_t>(u16()));
      case 0xce:
        return Value(static_cast<std::uint64_t>(u32()));
      case 0xcf:
        return Value(u64());
      case 0xd0:
        return Value(static_cast<std::int64_t>(static_cast<std::int8_t>(u8())));
      case 0xd1:
        return Value(static_cast<std::int64_t>(static_cast<std::int16_t>(u16())));
      case 0xd2:
        return Value(static_cast<std::int64_t>(static_cast<std::int32_t>(u32())));
      case 0xd3:
        return Value(static_cast<std::int64_t>(u64()));
      case 0xd9: {
        const std::size_t n = u8();
        const std::uint8_t* p = raw(n);
        Value v;
        v.type = Value::Type::Str;
        v.str.assign(reinterpret_cast<const char*>(p), n);
        return v;
      }
      case 0xda: {
        const std::size_t n = u16();
        const std::uint8_t* p = raw(n);
        Value v;
        v.type = Value::Type::Str;
        v.str.assign(reinterpret_cast<const char*>(p), n);
        return v;
      }
      case 0xdb: {
        const std::size_t n = u32();
        if (n > kMaxDecodeBytes) throw Error("msgpack string too large");
        const std::uint8_t* p = raw(n);
        Value v;
        v.type = Value::Type::Str;
        v.str.assign(reinterpret_cast<const char*>(p), n);
        return v;
      }
      case 0xdc: {
        const std::size_t n = u16();
        Value v;
        v.type = Value::Type::Array;
        v.array.reserve(n);
        for (std::size_t i = 0; i < n; ++i) v.array.push_back(read(depth + 1));
        return v;
      }
      case 0xdd: {
        const std::size_t n = u32();
        if (n > kMaxDecodeBytes / 4) throw Error("msgpack array too large");
        Value v;
        v.type = Value::Type::Array;
        v.array.reserve(n);
        for (std::size_t i = 0; i < n; ++i) v.array.push_back(read(depth + 1));
        return v;
      }
      case 0xde: {
        const std::size_t n = u16();
        Value v;
        v.type = Value::Type::Map;
        v.map.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
          Value key = read(depth + 1);
          if (key.type != Value::Type::Str) throw Error("msgpack map key must be a string");
          Value val = read(depth + 1);
          v.map.emplace_back(std::move(key.str), std::move(val));
        }
        return v;
      }
      case 0xdf: {
        const std::size_t n = u32();
        if (n > kMaxDecodeBytes / 4) throw Error("msgpack map too large");
        Value v;
        v.type = Value::Type::Map;
        v.map.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
          Value key = read(depth + 1);
          if (key.type != Value::Type::Str) throw Error("msgpack map key must be a string");
          Value val = read(depth + 1);
          v.map.emplace_back(std::move(key.str), std::move(val));
        }
        return v;
      }
      default:
        throw Error("unsupported msgpack marker");
    }
  }

 private:
  void require(std::size_t n) const {
    if (static_cast<std::size_t>(end_ - cursor_) < n) throw Error("truncated msgpack");
  }

  const std::uint8_t* begin_;
  const std::uint8_t* cursor_;
  const std::uint8_t* end_;
};

void encode_value(const Value& value, Writer& writer);

}  // namespace

Value Value::make_array(std::initializer_list<Value> values) {
  Value v;
  v.type = Type::Array;
  v.array.assign(values.begin(), values.end());
  return v;
}

Value Value::make_map(std::initializer_list<std::pair<std::string, Value>> values) {
  Value v;
  v.type = Type::Map;
  v.map.assign(values.begin(), values.end());
  return v;
}

bool Value::has(std::string_view key) const { return find(key) != nullptr; }

const Value* Value::find(std::string_view key) const {
  if (type != Type::Map) return nullptr;
  for (const auto& [k, v] : map) {
    if (k == key) return &v;
  }
  return nullptr;
}

const Value& Value::at(std::string_view key) const {
  const Value* v = find(key);
  if (!v) throw Error("msgpack key missing: " + std::string(key));
  return *v;
}

const std::string& Value::as_str() const {
  if (type != Type::Str) throw Error("msgpack value is not a string");
  return str;
}

const Bytes& Value::as_bin() const {
  if (type != Type::Bin) throw Error("msgpack value is not binary");
  return bin;
}

std::uint64_t Value::as_uint() const {
  if (type == Type::UInt) return uinteger;
  if (type == Type::Int && integer >= 0) return static_cast<std::uint64_t>(integer);
  throw Error("msgpack value is not an unsigned integer");
}

std::int64_t Value::as_int() const {
  if (type == Type::Int) return integer;
  if (type == Type::UInt && uinteger <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    return static_cast<std::int64_t>(uinteger);
  }
  throw Error("msgpack value is not an integer");
}

bool Value::as_bool() const {
  if (type != Type::Bool) throw Error("msgpack value is not a bool");
  return boolean;
}

const std::vector<Value>& Value::as_array() const {
  if (type != Type::Array) throw Error("msgpack value is not an array");
  return array;
}

const std::vector<std::pair<std::string, Value>>& Value::as_map() const {
  if (type != Type::Map) throw Error("msgpack value is not a map");
  return map;
}

PublicKey Value::as_public_key() const {
  const Bytes& b = as_bin();
  if (b.size() != kPublicKeyBytes) throw Error("invalid public key length");
  PublicKey pk{};
  std::copy(b.begin(), b.end(), pk.begin());
  return pk;
}

SessionId Value::as_session_id() const {
  const Bytes& b = as_bin();
  if (b.size() != kSessionIdBytes) throw Error("invalid session id length");
  SessionId sid{};
  std::copy(b.begin(), b.end(), sid.begin());
  return sid;
}

void Writer::nil() { out_.push_back(0xc0); }

void Writer::boolean(bool value) { out_.push_back(value ? 0xc3 : 0xc2); }

void Writer::uint(std::uint64_t value) {
  if (value <= 0x7f) {
    out_.push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xff) {
    out_.push_back(0xcc);
    out_.push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xffff) {
    out_.push_back(0xcd);
    append_u16(out_, static_cast<std::uint16_t>(value));
  } else if (value <= 0xffffffffULL) {
    out_.push_back(0xce);
    append_u32(out_, static_cast<std::uint32_t>(value));
  } else {
    out_.push_back(0xcf);
    append_u64(out_, value);
  }
}

void Writer::integer(std::int64_t value) {
  if (value >= 0) {
    uint(static_cast<std::uint64_t>(value));
    return;
  }
  if (value >= -32) {
    out_.push_back(static_cast<std::uint8_t>(static_cast<std::int8_t>(value)));
  } else if (value >= -128) {
    out_.push_back(0xd0);
    out_.push_back(static_cast<std::uint8_t>(static_cast<std::int8_t>(value)));
  } else if (value >= -32768) {
    out_.push_back(0xd1);
    append_u16(out_, static_cast<std::uint16_t>(static_cast<std::int16_t>(value)));
  } else if (value >= -2147483648LL) {
    out_.push_back(0xd2);
    append_u32(out_, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)));
  } else {
    out_.push_back(0xd3);
    append_u64(out_, static_cast<std::uint64_t>(value));
  }
}

void Writer::real(double value) {
  out_.push_back(0xcb);
  std::uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  append_u64(out_, bits);
}

void Writer::str(std::string_view value) {
  if (value.size() <= 31) {
    out_.push_back(static_cast<std::uint8_t>(0xa0 | value.size()));
  } else if (value.size() <= 0xff) {
    out_.push_back(0xd9);
    out_.push_back(static_cast<std::uint8_t>(value.size()));
  } else if (value.size() <= 0xffff) {
    out_.push_back(0xda);
    append_u16(out_, static_cast<std::uint16_t>(value.size()));
  } else {
    out_.push_back(0xdb);
    append_u32(out_, static_cast<std::uint32_t>(value.size()));
  }
  out_.insert(out_.end(), value.begin(), value.end());
}

void Writer::bin(const std::uint8_t* data, std::size_t size) {
  if (size <= 0xff) {
    out_.push_back(0xc4);
    out_.push_back(static_cast<std::uint8_t>(size));
  } else if (size <= 0xffff) {
    out_.push_back(0xc5);
    append_u16(out_, static_cast<std::uint16_t>(size));
  } else {
    out_.push_back(0xc6);
    append_u32(out_, static_cast<std::uint32_t>(size));
  }
  if (size > 0) out_.insert(out_.end(), data, data + size);
}

void Writer::bin(const Bytes& value) { bin(value.data(), value.size()); }

void Writer::array(std::size_t size) {
  if (size <= 15) {
    out_.push_back(static_cast<std::uint8_t>(0x90 | size));
  } else if (size <= 0xffff) {
    out_.push_back(0xdc);
    append_u16(out_, static_cast<std::uint16_t>(size));
  } else {
    out_.push_back(0xdd);
    append_u32(out_, static_cast<std::uint32_t>(size));
  }
}

void Writer::map(std::size_t size) {
  if (size <= 15) {
    out_.push_back(static_cast<std::uint8_t>(0x80 | size));
  } else if (size <= 0xffff) {
    out_.push_back(0xde);
    append_u16(out_, static_cast<std::uint16_t>(size));
  } else {
    out_.push_back(0xdf);
    append_u32(out_, static_cast<std::uint32_t>(size));
  }
}

namespace {

void encode_value(const Value& value, Writer& writer) {
  switch (value.type) {
    case Value::Type::Nil:
      writer.nil();
      break;
    case Value::Type::Bool:
      writer.boolean(value.boolean);
      break;
    case Value::Type::Int:
      writer.integer(value.integer);
      break;
    case Value::Type::UInt:
      writer.uint(value.uinteger);
      break;
    case Value::Type::Double:
      writer.real(value.real);
      break;
    case Value::Type::Str:
      writer.str(value.str);
      break;
    case Value::Type::Bin:
      writer.bin(value.bin);
      break;
    case Value::Type::Array:
      writer.array(value.array.size());
      for (const auto& item : value.array) encode_value(item, writer);
      break;
    case Value::Type::Map:
      writer.map(value.map.size());
      for (const auto& [key, item] : value.map) {
        writer.str(key);
        encode_value(item, writer);
      }
      break;
  }
}

}  // namespace

Bytes encode(const Value& value) {
  Writer writer;
  encode_value(value, writer);
  return writer.take();
}

Value decode(const std::uint8_t* data, std::size_t size) {
  if (!data && size > 0) throw Error("null msgpack data");
  if (size > kMaxDecodeBytes) throw Error("msgpack input too large");
  Reader reader(data, size);
  Value value = reader.read(0);
  if (reader.remaining() != 0) throw Error("trailing msgpack bytes");
  return value;
}

Value decode(const Bytes& data) { return decode(data.data(), data.size()); }

}  // namespace jn::msg
