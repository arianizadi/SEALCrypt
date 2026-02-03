// Test: HomomorphicInt::power()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Power) {
  ASSERT_TRUE(keys->generateRelinKeys());

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(2, 10);

  std::int64_t base = dist(gen);
  std::uint64_t exponent = 3;
  std::int64_t expected = base * base * base;

  auto enc = sealcrypt::HomomorphicInt::encrypt(base, *ctx, *keys);
  auto enc_pow = enc.power(exponent, *ctx, *keys);

  ASSERT_TRUE(enc_pow.isValid());

  std::int64_t result = enc_pow.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected) << base << "^" << exponent << " = " << result
                              << ", expected " << expected;
}
