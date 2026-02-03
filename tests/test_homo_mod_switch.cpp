// Test: HomomorphicInt::modSwitchToNext()

#include "sealcrypt/sealcrypt.hpp"
#include "test_fixtures.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace sealcrypt::test;

TEST(HomomorphicIntTest, ModSwitchToNext) {
  // Need higher security level for mod switching
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
  ASSERT_TRUE(ctx.isValid());

  sealcrypt::KeyPair keys(ctx);
  ASSERT_TRUE(keys.generate());

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 1000);

  std::int64_t value = dist(gen);

  auto enc = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
  auto enc_switched = enc.modSwitchToNext(ctx);

  ASSERT_TRUE(enc_switched.isValid());

  // Value should remain the same
  std::int64_t result = enc_switched.decrypt(ctx, keys);
  EXPECT_EQ(result, value) << "Value changed after modSwitchToNext: " << result
                           << ", expected " << value;
}
