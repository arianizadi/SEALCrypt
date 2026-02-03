// Test: HomomorphicInt::save() and load()

#include "sealcrypt/sealcrypt.hpp"

#include <cstdio>
#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::save() and load()" << std::endl;

  const char* path = "test_ciphertext.bin";

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(0, 10000);

  std::int64_t value = dist(gen);

  // Encrypt and save
  auto enc = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
  if(!enc.save(path, ctx)) {
    std::cerr << "FAIL: save() returned false" << std::endl;
    std::cerr << "Error: " << enc.getLastError() << std::endl;
    return 1;
  }

  // Load into new object
  sealcrypt::HomomorphicInt loaded;
  if(!loaded.load(path, ctx)) {
    std::cerr << "FAIL: load() returned false" << std::endl;
    std::cerr << "Error: " << loaded.getLastError() << std::endl;
    remove(path);
    return 1;
  }

  if(!loaded.isValid()) {
    std::cerr << "FAIL: loaded ciphertext is invalid" << std::endl;
    remove(path);
    return 1;
  }

  // Decrypt and verify
  std::int64_t result = loaded.decrypt(ctx, keys);
  if(result != value) {
    std::cerr << "FAIL: loaded value " << result << " != original " << value
              << std::endl;
    remove(path);
    return 1;
  }

  remove(path);
  std::cout << "PASS" << std::endl;
  return 0;
}
