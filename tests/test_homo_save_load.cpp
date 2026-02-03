// Test: HomomorphicInt::save() and load()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <cstdio>
#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, SaveLoad) {
  const char* path = "test_ciphertext.bin";

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 10000);

  std::int64_t value = dist(gen);

  // Encrypt and save
  auto enc = sealcrypt::HomomorphicInt::encrypt(value, *ctx, *keys);
  ASSERT_TRUE(enc.save(path, *ctx)) << "Error: " << enc.getLastError();

  // Load into new object
  sealcrypt::HomomorphicInt loaded;
  ASSERT_TRUE(loaded.load(path, *ctx)) << "Error: " << loaded.getLastError();
  EXPECT_TRUE(loaded.isValid());

  // Decrypt and verify
  std::int64_t result = loaded.decrypt(*ctx, *keys);
  EXPECT_EQ(result, value) << "Loaded value " << result << " != original "
                           << value;

  remove(path);
}
