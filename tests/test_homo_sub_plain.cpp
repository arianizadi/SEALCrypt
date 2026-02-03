// Test: HomomorphicInt::subPlain()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::subPlain()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());

  std::int64_t a
      = std::uniform_int_distribution< std::int64_t >(500, 1000)(gen);
  std::int64_t b = std::uniform_int_distribution< std::int64_t >(0, 500)(gen);
  std::int64_t expected = a - b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
  auto enc_result = enc_a.subPlain(b, ctx);

  if(!enc_result.isValid()) {
    std::cerr << "FAIL: subPlain() returned invalid result" << std::endl;
    return 1;
  }

  std::int64_t result = enc_result.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: " << a << " - " << b << " (plain) = " << result
              << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
