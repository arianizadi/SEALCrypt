// Test: HomomorphicInt::isValid()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, IsValid) {
  // Default constructed should be invalid
  sealcrypt::HomomorphicInt empty;
  EXPECT_FALSE(empty.isValid());

  // Encrypted value should be valid
  auto encrypted = sealcrypt::HomomorphicInt::encrypt(42, *ctx, *keys);
  EXPECT_TRUE(encrypted.isValid());
}
