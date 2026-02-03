// Test: HomomorphicInt::isTransparent()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::isTransparent()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  auto enc = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);

  // Properly encrypted ciphertext should NOT be transparent
  // (transparent = can be decrypted without secret key = security risk)
  if(enc.isTransparent()) {
    std::cerr << "FAIL: encrypted ciphertext should not be transparent"
              << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
