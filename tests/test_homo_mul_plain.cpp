// Test: HomomorphicInt::mulPlain()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, MulPlain) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 100);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t expected = a * b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
  auto enc_result = enc_a.mulPlain(b, *ctx);

  ASSERT_TRUE(enc_result.isValid());

  std::int64_t result = enc_result.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected) << a << " * " << b << " (plain) = " << result
                              << ", expected " << expected;
}
