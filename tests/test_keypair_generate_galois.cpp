// Test: KeyPair::generateGaloisKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::generateGaloisKeys()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Generate base keys first
  if(!keys.generate()) {
    std::cerr << "FAIL: generate() failed" << std::endl;
    return 1;
  }

  // Should not have galois keys yet
  if(keys.hasGaloisKeys()) {
    std::cerr << "FAIL: hasGaloisKeys() true before generateGaloisKeys()"
              << std::endl;
    return 1;
  }

  // Generate galois keys
  if(!keys.generateGaloisKeys()) {
    std::cerr << "FAIL: generateGaloisKeys() returned false" << std::endl;
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return 1;
  }

  // Should have galois keys now
  if(!keys.hasGaloisKeys()) {
    std::cerr << "FAIL: hasGaloisKeys() false after generateGaloisKeys()"
              << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
