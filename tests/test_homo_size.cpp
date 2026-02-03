// Test: HomomorphicInt::size()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, Size) {
  auto enc = sealcrypt::HomomorphicInt::encrypt(42, *ctx, *keys);

  // Fresh ciphertext should have size 2
  EXPECT_EQ(enc.size(), static_cast< std::size_t >(2))
      << "Fresh ciphertext size should be 2";

  // After multiplication (without relinearization), size should increase
  auto enc_prod = enc * enc;
  EXPECT_GE(enc_prod.size(), static_cast< std::size_t >(2))
      << "Ciphertext size after multiplication should be >= 2";
}
