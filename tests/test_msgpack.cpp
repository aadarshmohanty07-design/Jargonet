#include <string>

#include "core/msgpack.hpp"
#include "test_util.hpp"

using namespace jn;
using namespace jn::msg;

void run() {
  Writer writer;
  writer.map(9);
  writer.str("nil");
  writer.nil();
  writer.str("bool");
  writer.boolean(true);
  writer.str("uint");
  writer.uint(5000000000ULL);
  writer.str("int");
  writer.integer(-129);
  writer.str("double");
  writer.real(3.5);
  writer.str("str");
  writer.str("hello msgpack");
  writer.str("bin");
  Bytes binary{0, 1, 2, 255};
  writer.bin(binary);
  writer.str("array");
  writer.array(3);
  writer.uint(1);
  writer.str("two");
  writer.boolean(false);
  writer.str("map");
  writer.map(1);
  writer.str("nested");
  writer.uint(7);
  Bytes encoded = writer.take();

  Value root = decode(encoded);
  CHECK(root.type == Value::Type::Map);
  CHECK(root.at("nil").is_nil());
  CHECK(root.at("bool").as_bool());
  CHECK(root.at("uint").as_uint() == 5000000000ULL);
  CHECK(root.at("int").as_int() == -129);
  CHECK(root.at("double").type == Value::Type::Double);
  CHECK(root.at("str").as_str() == "hello msgpack");
  CHECK(root.at("bin").as_bin() == binary);
  CHECK(root.at("array").as_array().size() == 3);
  CHECK(root.at("array").as_array()[1].as_str() == "two");
  CHECK(root.at("map").at("nested").as_uint() == 7);

  Bytes reencoded = encode(root);
  CHECK(reencoded == encoded);

  CHECK_THROWS(decode(encoded.data(), encoded.size() - 1));
  Bytes trailing = encoded;
  trailing.push_back(0x00);
  CHECK_THROWS(decode(trailing));
  CHECK_THROWS(decode(nullptr, 0));
  CHECK_THROWS(decode(Bytes{}));

  // Fixed-width encodings round-trip.
  Writer long_writer;
  long_writer.map(3);
  long_writer.str("s16");
  long_writer.str(std::string(200, 'x'));
  long_writer.str("b16");
  long_writer.bin(Bytes(300, 0xAB));
  long_writer.str("a16");
  long_writer.array(20);
  for (int i = 0; i < 20; ++i) long_writer.integer(-i);
  Value long_value = decode(long_writer.take());
  CHECK(long_value.at("s16").as_str().size() == 200);
  CHECK(long_value.at("b16").as_bin().size() == 300);
  CHECK(long_value.at("a16").as_array().size() == 20);

  // Strict typing.
  CHECK_THROWS(root.at("str").as_uint());
  CHECK_THROWS(root.at("bin").as_str());
  CHECK_THROWS(root.at("missing"));

  // Public-key helpers reject wrong lengths.
  Writer pk_writer;
  pk_writer.map(1);
  pk_writer.str("pk");
  pk_writer.bin(Bytes(31, 1));
  Value short_pk = decode(pk_writer.take());
  CHECK_THROWS(short_pk.at("pk").as_public_key());

  // Large local values are supported; container counts cannot force huge
  // allocations from a tiny input.
  Writer large_writer;
  large_writer.bin(Bytes(2 * 1024 * 1024, 0xAA));
  Value large_value = decode(large_writer.take());
  CHECK(large_value.as_bin().size() == 2 * 1024 * 1024);
  CHECK_THROWS(decode(Bytes{0xdd, 0xff, 0xff, 0xff, 0xff}));
  CHECK_THROWS(decode(Bytes{0xdf, 0xff, 0xff, 0xff, 0xff}));

  // Deep nesting is bounded.
  Bytes deep;
  for (int i = 0; i < 20; ++i) {
    Writer w;
    w.array(1);
    Bytes prefix = w.take();
    deep.insert(deep.end(), prefix.begin(), prefix.end());
  }
  CHECK_THROWS(decode(deep));
}

TEST_MAIN()
