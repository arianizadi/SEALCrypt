// Test: Chained homomorphic operations (a + b) * c

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, ChainedOperations) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 50);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t c = dist(gen);
  std::int64_t expected = (a + b) * c;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, *ctx, *keys);
  auto enc_c = sealcrypt::HomomorphicInt::encrypt(c, *ctx, *keys);

  auto enc_result = (enc_a + enc_b) * enc_c;

  ASSERT_TRUE(enc_result.isValid());

  std::int64_t result = enc_result.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected) << "(" << a << " + " << b << ") * " << c << " = "
                              << result << ", expected " << expected;
}
