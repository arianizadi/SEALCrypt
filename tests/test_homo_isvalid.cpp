// Test: HomomorphicInt::isValid()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::isValid()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  // Default constructed should be invalid
  sealcrypt::HomomorphicInt empty;
  if(empty.isValid()) {
    std::cerr << "FAIL: default constructed isValid() returned true"
              << std::endl;
    return 1;
  }

  // Encrypted value should be valid
  auto encrypted = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);
  if(!encrypted.isValid()) {
    std::cerr << "FAIL: encrypted value isValid() returned false" << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
