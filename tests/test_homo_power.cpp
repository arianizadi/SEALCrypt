// Test: HomomorphicInt::power()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::power()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }
  if(!keys.generateRelinKeys()) {
    std::cerr << "FAIL: keys.generateRelinKeys() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(2, 10);

  std::int64_t base = dist(gen);
  std::uint64_t exponent = 3;
  std::int64_t expected = base * base * base;

  auto enc = sealcrypt::HomomorphicInt::encrypt(base, ctx, keys);
  auto enc_pow = enc.power(exponent, ctx, keys);

  if(!enc_pow.isValid()) {
    std::cerr << "FAIL: power() returned invalid result" << std::endl;
    return 1;
  }

  std::int64_t result = enc_pow.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: " << base << "^" << exponent << " = " << result
              << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
