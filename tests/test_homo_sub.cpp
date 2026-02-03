// Test: HomomorphicInt::operator-

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::operator-" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());

  for(int i = 0; i < 5; i++) {
    // Ensure a > b for positive result
    std::int64_t a
        = std::uniform_int_distribution< std::int64_t >(500, 1000)(gen);
    std::int64_t b = std::uniform_int_distribution< std::int64_t >(0, 500)(gen);
    std::int64_t expected = a - b;

    auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
    auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, ctx, keys);
    auto enc_diff = enc_a - enc_b;

    if(!enc_diff.isValid()) {
      std::cerr << "FAIL: subtraction result is invalid" << std::endl;
      return 1;
    }

    std::int64_t result = enc_diff.decrypt(ctx, keys);
    if(result != expected) {
      std::cerr << "FAIL: " << a << " - " << b << " = " << result
                << ", expected " << expected << std::endl;
      return 1;
    }
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
