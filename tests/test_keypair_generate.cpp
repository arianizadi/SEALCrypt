// Test: KeyPair::generate()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::generate()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Before generate - should not have keys
  if(keys.hasPublicKey()) {
    std::cerr << "FAIL: hasPublicKey() true before generate()" << std::endl;
    return 1;
  }
  if(keys.hasSecretKey()) {
    std::cerr << "FAIL: hasSecretKey() true before generate()" << std::endl;
    return 1;
  }

  // Generate keys
  if(!keys.generate()) {
    std::cerr << "FAIL: generate() returned false" << std::endl;
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return 1;
  }

  // After generate - should have keys
  if(!keys.hasPublicKey()) {
    std::cerr << "FAIL: hasPublicKey() false after generate()" << std::endl;
    return 1;
  }
  if(!keys.hasSecretKey()) {
    std::cerr << "FAIL: hasSecretKey() false after generate()" << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
