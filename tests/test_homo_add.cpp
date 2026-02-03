// Test: HomomorphicInt::operator+

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Addition) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 1000);

  for(int i = 0; i < 5; i++) {
    std::int64_t a = dist(gen);
    std::int64_t b = dist(gen);
    std::int64_t expected = a + b;

    auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
    ASSERT_TRUE(enc_a.isValid()) << "Failed to encrypt " << a;

    auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, *ctx, *keys);
    ASSERT_TRUE(enc_b.isValid()) << "Failed to encrypt " << b;

    auto enc_sum = enc_a + enc_b;
    ASSERT_TRUE(enc_sum.isValid()) << "Addition result is invalid";

    std::int64_t result = enc_sum.decrypt(*ctx, *keys);
    EXPECT_EQ(result, expected)
        << a << " + " << b << " = " << result << ", expected " << expected;
  }
}

TEST(HomomorphicIntTest, AdditionWithInvalidOperands) {
  sealcrypt::HomomorphicInt invalid1;
  sealcrypt::HomomorphicInt invalid2;

  auto result = invalid1 + invalid2;
  EXPECT_FALSE(result.isValid());
}
