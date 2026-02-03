// Test: KeyPair::generateAll()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::generateAll()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Generate all keys at once
  if(!keys.generateAll()) {
    std::cerr << "FAIL: generateAll() returned false" << std::endl;
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return 1;
  }

  // Should have all key types
  if(!keys.hasPublicKey()) {
    std::cerr << "FAIL: hasPublicKey() false after generateAll()" << std::endl;
    return 1;
  }
  if(!keys.hasSecretKey()) {
    std::cerr << "FAIL: hasSecretKey() false after generateAll()" << std::endl;
    return 1;
  }
  if(!keys.hasRelinKeys()) {
    std::cerr << "FAIL: hasRelinKeys() false after generateAll()" << std::endl;
    return 1;
  }
  if(!keys.hasGaloisKeys()) {
    std::cerr << "FAIL: hasGaloisKeys() false after generateAll()" << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
