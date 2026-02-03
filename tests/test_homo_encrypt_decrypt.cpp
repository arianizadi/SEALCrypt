// Test: HomomorphicInt::encrypt() and decrypt()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::encrypt() and decrypt()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  // Test with random values
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 10000);

  for(int i = 0; i < 5; i++) {
    std::int64_t value = dist(gen);

    auto encrypted = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
    if(!encrypted.isValid()) {
      std::cerr << "FAIL: encrypt() returned invalid result for " << value
                << std::endl;
      std::cerr << "Error: " << encrypted.getLastError() << std::endl;
      return 1;
    }

    std::int64_t decrypted = encrypted.decrypt(ctx, keys);
    if(decrypted != value) {
      std::cerr << "FAIL: decrypt() returned " << decrypted << ", expected "
                << value << std::endl;
      return 1;
    }
  }

  std::cout << "PASS" << std::endl;
  return 0;
}
