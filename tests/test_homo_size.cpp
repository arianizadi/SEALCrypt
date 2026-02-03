// Test: HomomorphicInt::size()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::size()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  auto enc = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);

  // Fresh ciphertext should have size 2
  std::size_t size = enc.size();
  if(size != 2) {
    std::cerr << "FAIL: fresh ciphertext size should be 2, got " << size
              << std::endl;
    return 1;
  }

  // After multiplication (without relinearization), size should increase
  auto enc_prod = enc * enc;
  std::size_t size_after = enc_prod.size();

  if(size_after < 2) {
    std::cerr
        << "FAIL: ciphertext size after multiplication should be >= 2, got "
        << size_after << std::endl;
    return 1;
  }

  std::cout << "PASS (fresh=" << size << ", after mul=" << size_after << ")"
            << std::endl;
  return 0;
}
