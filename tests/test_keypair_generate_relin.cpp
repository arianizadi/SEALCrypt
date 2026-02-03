// Test: KeyPair::generateRelinKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <gtest/gtest.h>

TEST(KeyPairTest, GenerateRelinKeys) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Should fail without generate() first
  EXPECT_FALSE(keys.generateRelinKeys());

  // Generate base keys first
  ASSERT_TRUE(keys.generate());

  // Should not have relin keys yet
  EXPECT_FALSE(keys.hasRelinKeys());

  // Generate relin keys
  EXPECT_TRUE(keys.generateRelinKeys()) << "Error: " << keys.getLastError();

  // Should have relin keys now
  EXPECT_TRUE(keys.hasRelinKeys());
}
