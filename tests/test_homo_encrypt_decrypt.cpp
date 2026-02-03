// Test: HomomorphicInt::encrypt() and decrypt()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, EncryptDecrypt) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 10000);

  for(int i = 0; i < 5; i++) {
    std::int64_t value = dist(gen);

    auto encrypted = sealcrypt::HomomorphicInt::encrypt(value, *ctx, *keys);
    ASSERT_TRUE(encrypted.isValid())
        << "Failed to encrypt " << value << ": " << encrypted.getLastError();

    std::int64_t decrypted = encrypted.decrypt(*ctx, *keys);
    EXPECT_EQ(decrypted, value)
        << "Expected " << value << ", got " << decrypted;
  }
}

TEST(HomomorphicIntTest, EncryptInvalidContext) {
  sealcrypt::CryptoContext ctx(0, 0); // Invalid
  sealcrypt::KeyPair keys(ctx);

  auto encrypted = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);
  EXPECT_FALSE(encrypted.isValid());
}

TEST(HomomorphicIntTest, EncryptNoPublicKey) {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);
  // Don't generate keys

  auto encrypted = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);
  EXPECT_FALSE(encrypted.isValid());
}
