// Test: HomomorphicInt::operator- (unary negation)

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Negation) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 1000);

  std::int64_t value = dist(gen);

  auto enc = sealcrypt::HomomorphicInt::encrypt(value, *ctx, *keys);
  auto enc_neg = -enc;

  ASSERT_TRUE(enc_neg.isValid());

  // Original + negated should equal 0
  auto enc_sum = enc + enc_neg;
  std::int64_t result = enc_sum.decrypt(*ctx, *keys);

  EXPECT_EQ(result, 0) << value << " + (-" << value << ") = " << result
                       << ", expected 0";
}
