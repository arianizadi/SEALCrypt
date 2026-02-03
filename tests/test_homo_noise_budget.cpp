// Test: HomomorphicInt::noiseBudget()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>

using namespace sealcrypt::test;

TEST_F(CryptoTestFixture, NoiseBudget) {
  auto enc = sealcrypt::HomomorphicInt::encrypt(42, *ctx, *keys);

  int budget_initial = enc.noiseBudget(*ctx, *keys);
  EXPECT_GT(budget_initial, 0) << "Initial noise budget should be positive";

  // Multiplication consumes noise budget
  auto enc_squared = enc * enc;
  int budget_after_mul = enc_squared.noiseBudget(*ctx, *keys);

  EXPECT_LT(budget_after_mul, budget_initial)
      << "Noise budget should decrease after multiplication";
}
