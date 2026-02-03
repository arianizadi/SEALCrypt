// Test: KeyPair::saveRelinKeys() and loadRelinKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <cstdio>
#include <gtest/gtest.h>

TEST(KeyPairTest, SaveLoadRelinKeys) {
  const char* relin_path = "test_relin.key";

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);

  // Generate and save
  {
    sealcrypt::KeyPair keys(ctx);
    ASSERT_TRUE(keys.generate());
    ASSERT_TRUE(keys.generateRelinKeys());
    EXPECT_TRUE(keys.saveRelinKeys(relin_path))
        << "Error: " << keys.getLastError();
  }

  // Load into new KeyPair
  {
    sealcrypt::KeyPair keys(ctx);
    EXPECT_TRUE(keys.loadRelinKeys(relin_path))
        << "Error: " << keys.getLastError();
    EXPECT_TRUE(keys.hasRelinKeys());
  }

  remove(relin_path);
}
