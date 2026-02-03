// Test: KeyPair::generateRelinKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::generateRelinKeys()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  // Should fail without generate() first
  if(keys.generateRelinKeys()) {
    std::cerr << "FAIL: generateRelinKeys() succeeded without generate()"
              << std::endl;
    return 1;
  }

  // Generate base keys first
  if(!keys.generate()) {
    std::cerr << "FAIL: generate() failed" << std::endl;
    return 1;
  }

  // Should not have relin keys yet
  if(keys.hasRelinKeys()) {
    std::cerr << "FAIL: hasRelinKeys() true before generateRelinKeys()"
              << std::endl;
    return 1;
  }

  // Generate relin keys
  if(!keys.generateRelinKeys()) {
    std::cerr << "FAIL: generateRelinKeys() returned false" << std::endl;
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return 1;
  }

  // Should have relin keys now
  if(!keys.hasRelinKeys()) {
    std::cerr << "FAIL: hasRelinKeys() false after generateRelinKeys()"
              << std::endl;
    return 1;
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
