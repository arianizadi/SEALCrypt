// Test: HomomorphicInt::operator+

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::operator+" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 1000);

  for(int i = 0; i < 5; i++) {
    std::int64_t a = dist(gen);
    std::int64_t b = dist(gen);
    std::int64_t expected = a + b;

    auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
    auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, ctx, keys);
    auto enc_sum = enc_a + enc_b;

    if(!enc_sum.isValid()) {
      std::cerr << "FAIL: addition result is invalid" << std::endl;
      return 1;
    }

    std::int64_t result = enc_sum.decrypt(ctx, keys);
    if(result != expected) {
      std::cerr << "FAIL: " << a << " + " << b << " = " << result
                << ", expected " << expected << std::endl;
      return 1;
    }
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
