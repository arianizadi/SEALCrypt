// Test: HomomorphicInt::modSwitchToNext()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::modSwitchToNext()" << std::endl;

  // Need higher security level for mod switching
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
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
  auto enc_switched = enc.modSwitchToNext(ctx);

  if(!enc_switched.isValid()) {
    std::cerr << "FAIL: modSwitchToNext() returned invalid result" << std::endl;
    return 1;
  }

  // Value should remain the same
  std::int64_t result = enc_switched.decrypt(ctx, keys);
  if(result != value) {
    std::cerr << "FAIL: value changed after modSwitchToNext: " << result
              << ", expected " << value << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
