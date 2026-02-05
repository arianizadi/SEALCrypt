// Test: HomomorphicInt::operator- (unary negation)

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Negation) {
  std::int64_t val_a = randomInt(1, 500);
  std::int64_t val_b = randomInt(val_a + 1, 1000);

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(val_a, *ctx, *keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(val_b, *ctx, *keys);
  auto enc_neg_a = -enc_a;

  ASSERT_TRUE(enc_neg_a.isValid());

  // indirect test by b + (-a) because if we do a + (-a) it becomes a 0 with no noise
  // meaning 0 is the true value and is now transparent, causing an error in seals
  // security checks. we use b-a to test if negation works without calc on itself.
  auto enc_result = enc_b + enc_neg_a;
  ASSERT_TRUE(enc_result.isValid());

  std::int64_t result = enc_result.decrypt(*ctx, *keys);
  std::int64_t expected = val_b - val_a;

  EXPECT_EQ(result, expected)
      << val_b << " + (-" << val_a << ") = " << result << ", expected "
      << expected;
}
