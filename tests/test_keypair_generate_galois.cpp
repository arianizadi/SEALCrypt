// Test: KeyPair::generateGaloisKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <gtest/gtest.h>

TEST(KeyPairTest, GenerateGaloisKeys) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  ASSERT_TRUE(keys.generate());

  EXPECT_FALSE(keys.hasGaloisKeys());

  EXPECT_TRUE(keys.generateGaloisKeys()) << "Error: " << keys.getLastError();

  EXPECT_TRUE(keys.hasGaloisKeys());
}
