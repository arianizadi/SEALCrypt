// Test: HomomorphicInt::subPlain()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, SubPlain) {
  std::random_device rd;
  std::mt19937 gen(rd());

  std::int64_t a
      = std::uniform_int_distribution< std::int64_t >(500, 1000)(gen);
  std::int64_t b = std::uniform_int_distribution< std::int64_t >(0, 500)(gen);
  std::int64_t expected = a - b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
  auto enc_result = enc_a.subPlain(b, *ctx);

  ASSERT_TRUE(enc_result.isValid());

  std::int64_t result = enc_result.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected) << a << " - " << b << " (plain) = " << result
                              << ", expected " << expected;
}
