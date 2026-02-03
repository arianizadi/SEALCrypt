// Test: HomomorphicInt::isTransparent()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, IsTransparent) {
  auto enc = sealcrypt::HomomorphicInt::encrypt(42, *ctx, *keys);

  // Properly encrypted ciphertext should NOT be transparent
  // (transparent = can be decrypted without secret key = security risk)
  EXPECT_FALSE(enc.isTransparent())
      << "Encrypted ciphertext should not be transparent";
}
