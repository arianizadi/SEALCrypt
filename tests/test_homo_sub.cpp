// Test: HomomorphicInt::operator-

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Subtraction) {
  std::random_device rd;
  std::mt19937 gen(rd());

  for(int i = 0; i < 5; i++) {
    // Ensure a > b for positive result
    std::int64_t a
        = std::uniform_int_distribution< std::int64_t >(500, 1000)(gen);
    std::int64_t b = std::uniform_int_distribution< std::int64_t >(0, 500)(gen);
    std::int64_t expected = a - b;

    auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
    auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, *ctx, *keys);
    auto enc_diff = enc_a - enc_b;

    ASSERT_TRUE(enc_diff.isValid());

    std::int64_t result = enc_diff.decrypt(*ctx, *keys);
    EXPECT_EQ(result, expected)
        << a << " - " << b << " = " << result << ", expected " << expected;
  }
}
