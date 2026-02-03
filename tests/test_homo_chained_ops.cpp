// Test: Chained homomorphic operations (a + b) * c

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: Chained operations (a + b) * c" << std::endl;

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
  std::int64_t c = dist(gen);
  std::int64_t expected = (a + b) * c;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, ctx, keys);
  auto enc_c = sealcrypt::HomomorphicInt::encrypt(c, ctx, keys);

  auto enc_result = (enc_a + enc_b) * enc_c;

  if(!enc_result.isValid()) {
    std::cerr << "FAIL: chained operation result is invalid" << std::endl;
    return 1;
  }

  std::int64_t result = enc_result.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: (" << a << " + " << b << ") * " << c << " = " << result
              << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS: (" << a << " + " << b << ") * " << c << " = " << result
            << std::endl;
  return 0;
}
