// Test: HomomorphicInt::square()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::square()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 100);

  std::int64_t value = dist(gen);
  std::int64_t expected = value * value;

  auto enc = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
  auto enc_squared = enc.square(ctx);

  if(!enc_squared.isValid()) {
    std::cerr << "FAIL: square() returned invalid result" << std::endl;
    return 1;
  }

  std::int64_t result = enc_squared.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: " << value << "^2 = " << result << ", expected "
              << expected << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
