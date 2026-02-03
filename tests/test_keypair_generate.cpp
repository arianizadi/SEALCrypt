// Test: KeyPair::generate()

#include "sealcrypt/sealcrypt.hpp"

#include <gtest/gtest.h>

TEST(KeyPairTest, Generate) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Before generate - should not have keys
  EXPECT_FALSE(keys.hasPublicKey());
  EXPECT_FALSE(keys.hasSecretKey());

  // Generate keys
  EXPECT_TRUE(keys.generate()) << "Error: " << keys.getLastError();

  // After generate - should have keys
  EXPECT_TRUE(keys.hasPublicKey());
  EXPECT_TRUE(keys.hasSecretKey());
}

TEST(KeyPairTest, GenerateInvalidContext) {
  sealcrypt::CryptoContext ctx(0, 0); // Invalid
  sealcrypt::KeyPair keys(ctx);

  EXPECT_FALSE(keys.generate());
  EXPECT_FALSE(keys.hasPublicKey());
  EXPECT_FALSE(keys.hasSecretKey());
}
