// Test: KeyPair::generateAll()

#include "sealcrypt/sealcrypt.hpp"

#include <gtest/gtest.h>

TEST(KeyPairTest, GenerateAll) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  EXPECT_TRUE(keys.generateAll()) << "Error: " << keys.getLastError();

  EXPECT_TRUE(keys.hasPublicKey());
  EXPECT_TRUE(keys.hasSecretKey());
  EXPECT_TRUE(keys.hasRelinKeys());
  EXPECT_TRUE(keys.hasGaloisKeys());
}
