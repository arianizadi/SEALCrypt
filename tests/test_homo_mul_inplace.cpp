// Test: HomomorphicInt::operator*=

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, InPlaceMultiplication) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 50);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t expected = a * b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, *ctx, *keys);

  enc_a *= enc_b;

  std::int64_t result = enc_a.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected)
      << a << " *= " << b << " = " << result << ", expected " << expected;
}
