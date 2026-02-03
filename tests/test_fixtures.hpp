#pragma once

#include "sealcrypt/sealcrypt.hpp"

#include <gtest/gtest.h>
#include <random>

namespace sealcrypt::test {

  /// Test fixture for common setup (context and keys)
  class CryptoTestFixture : public ::testing::Test {
  protected:
    auto SetUp() -> void override {
      ctx = std::make_unique< sealcrypt::CryptoContext >(
          sealcrypt::SecurityLevel::Low);
      ASSERT_TRUE(ctx->isValid()) << "Failed to create crypto context";

      keys = std::make_unique< sealcrypt::KeyPair >(*ctx);
      ASSERT_TRUE(keys->generate())
          << "Failed to generate keys: " << keys->getLastError();
    }

    auto TearDown() -> void override {
      keys.reset();
      ctx.reset();
    }

    std::unique_ptr< sealcrypt::CryptoContext > ctx;
    std::unique_ptr< sealcrypt::KeyPair > keys;

    // Helper for random integers
    static auto randomInt(std::int64_t min, std::int64_t max) -> std::int64_t {
      static std::mt19937 gen(std::random_device {}());
      std::uniform_int_distribution< std::int64_t > dist(min, max);
      return dist(gen);
    }
  };

} // namespace sealcrypt::test
