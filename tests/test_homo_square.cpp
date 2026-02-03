// Test: HomomorphicInt::square()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Square) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 100);

  std::int64_t value = dist(gen);
  std::int64_t expected = value * value;

  auto enc = sealcrypt::HomomorphicInt::encrypt(value, *ctx, *keys);
  auto enc_squared = enc.square(*ctx);

  ASSERT_TRUE(enc_squared.isValid());

  std::int64_t result = enc_squared.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected)
      << value << "^2 = " << result << ", expected " << expected;
}
