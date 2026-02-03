// Test: HomomorphicInt::relinearize()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Relinearize) {
  ASSERT_TRUE(keys->generateRelinKeys());

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 50);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t expected = a * b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, *ctx, *keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, *ctx, *keys);

  // Multiply increases ciphertext size
  auto enc_prod = enc_a * enc_b;
  std::size_t size_before = enc_prod.size();

  // Relinearize should reduce size
  auto enc_relin = enc_prod.relinearize(*ctx, *keys);
  std::size_t size_after = enc_relin.size();

  ASSERT_TRUE(enc_relin.isValid());
  EXPECT_LE(size_after, size_before)
      << "Size should not increase after relinearize";

  // Result should still be correct
  std::int64_t result = enc_relin.decrypt(*ctx, *keys);
  EXPECT_EQ(result, expected) << "Result changed after relinearize: " << result
                              << ", expected " << expected;
}
