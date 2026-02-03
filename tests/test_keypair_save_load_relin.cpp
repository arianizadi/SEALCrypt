// Test: KeyPair::saveRelinKeys() and loadRelinKeys()

#include "sealcrypt/sealcrypt.hpp"

#include <cstdio>
#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::saveRelinKeys() and loadRelinKeys()"
            << std::endl;

  const char* relin_path = "test_relin.key";

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);

  // Generate and save
  {
    sealcrypt::KeyPair keys(ctx);
    if(!keys.generate()) {
      std::cerr << "FAIL: generate() failed" << std::endl;
      return 1;
    }
    if(!keys.generateRelinKeys()) {
      std::cerr << "FAIL: generateRelinKeys() failed" << std::endl;
      return 1;
    }

    if(!keys.saveRelinKeys(relin_path)) {
      std::cerr << "FAIL: saveRelinKeys() returned false" << std::endl;
      std::cerr << "Error: " << keys.getLastError() << std::endl;
      return 1;
    }
  }

  // Load into new KeyPair
  {
    sealcrypt::KeyPair keys(ctx);

    if(!keys.loadRelinKeys(relin_path)) {
      std::cerr << "FAIL: loadRelinKeys() returned false" << std::endl;
      std::cerr << "Error: " << keys.getLastError() << std::endl;
      remove(relin_path);
      return 1;
    }

    if(!keys.hasRelinKeys()) {
      std::cerr << "FAIL: hasRelinKeys() false after loadRelinKeys()"
                << std::endl;
      remove(relin_path);
      return 1;
    }
  }

  remove(relin_path);
  std::cout << "PASS" << std::endl;
  return 0;
}
