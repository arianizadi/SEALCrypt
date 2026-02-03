// Test: HomomorphicInt::operator*=

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::operator*=" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 50);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t expected = a * b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, ctx, keys);

  enc_a *= enc_b;

  std::int64_t result = enc_a.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: " << a << " *= " << b << " = " << result
              << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
