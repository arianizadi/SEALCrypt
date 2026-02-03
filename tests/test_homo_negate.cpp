// Test: HomomorphicInt::operator- (unary negation)

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::operator- (unary negation)" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 1000);

  std::int64_t value = dist(gen);

  auto enc = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
  auto enc_neg = -enc;

  if(!enc_neg.isValid()) {
    std::cerr << "FAIL: negation result is invalid" << std::endl;
    return 1;
  }

  // Original + negated should equal 0
  auto enc_sum = enc + enc_neg;
  std::int64_t result = enc_sum.decrypt(ctx, keys);

  if(result != 0) {
    std::cerr << "FAIL: " << value << " + (-" << value << ") = " << result
              << ", expected 0" << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
