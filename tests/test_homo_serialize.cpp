// Test: HomomorphicInt::serialize() and deserialize()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::serialize() and deserialize()"
            << std::endl;

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

  // Encrypt and serialize
  auto enc = sealcrypt::HomomorphicInt::encrypt(value, ctx, keys);
  auto bytes = enc.serialize(ctx);

  if(bytes.empty()) {
    std::cerr << "FAIL: serialize() returned empty vector" << std::endl;
    return 1;
  }

  // Deserialize into new object
  sealcrypt::HomomorphicInt deserialized;
  if(!deserialized.deserialize(bytes, ctx)) {
    std::cerr << "FAIL: deserialize() returned false" << std::endl;
    std::cerr << "Error: " << deserialized.getLastError() << std::endl;
    return 1;
  }

  if(!deserialized.isValid()) {
    std::cerr << "FAIL: deserialized ciphertext is invalid" << std::endl;
    return 1;
  }

  // Decrypt and verify
  std::int64_t result = deserialized.decrypt(ctx, keys);
  if(result != value) {
    std::cerr << "FAIL: deserialized value " << result << " != original "
              << value << std::endl;
    return 1;
  }

  std::cout << "PASS (serialized to " << bytes.size() << " bytes)" << std::endl;
  return 0;
}
