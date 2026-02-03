// Test: KeyPair::save() and load()

#include "sealcrypt/sealcrypt.hpp"

#include <cstdio>
#include <gtest/gtest.h>

TEST(KeyPairTest, SaveLoad) {
  const char* pub_path = "test_pub.key";
  const char* sec_path = "test_sec.key";

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);

  // Generate and save
  {
    sealcrypt::KeyPair keys(ctx);
    ASSERT_TRUE(keys.generate());
    EXPECT_TRUE(keys.save(pub_path, sec_path))
        << "Error: " << keys.getLastError();
  }

  // Load into new KeyPair
  {
    sealcrypt::KeyPair keys(ctx);
    EXPECT_TRUE(keys.load(pub_path, sec_path))
        << "Error: " << keys.getLastError();
    EXPECT_TRUE(keys.hasPublicKey());
    EXPECT_TRUE(keys.hasSecretKey());
  }

  remove(pub_path);
  remove(sec_path);
}

TEST(KeyPairTest, LoadNonexistentFile) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  EXPECT_FALSE(keys.loadPublicKey("nonexistent.key"));
  EXPECT_FALSE(keys.loadSecretKey("nonexistent.key"));
}
