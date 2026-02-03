// Test: HomomorphicInt::serialize() and deserialize()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, SerializeDeserialize) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 10000);

  std::int64_t value = dist(gen);

  // Encrypt and serialize
  auto enc = sealcrypt::HomomorphicInt::encrypt(value, *ctx, *keys);
  auto bytes = enc.serialize(*ctx);

  EXPECT_FALSE(bytes.empty()) << "Serialized data should not be empty";

  // Deserialize into new object
  sealcrypt::HomomorphicInt deserialized;
  ASSERT_TRUE(deserialized.deserialize(bytes, *ctx))
      << "Error: " << deserialized.getLastError();
  EXPECT_TRUE(deserialized.isValid());

  // Decrypt and verify
  std::int64_t result = deserialized.decrypt(*ctx, *keys);
  EXPECT_EQ(result, value) << "Deserialized value " << result << " != original "
                           << value;
}
