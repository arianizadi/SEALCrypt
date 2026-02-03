// Test: HomomorphicInt::relinearize()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <random>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::relinearize()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }
  if(!keys.generateRelinKeys()) {
    std::cerr << "FAIL: keys.generateRelinKeys() failed" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution< std::int64_t > dist(1, 50);

  std::int64_t a = dist(gen);
  std::int64_t b = dist(gen);
  std::int64_t expected = a * b;

  auto enc_a = sealcrypt::HomomorphicInt::encrypt(a, ctx, keys);
  auto enc_b = sealcrypt::HomomorphicInt::encrypt(b, ctx, keys);

  // Multiply increases ciphertext size
  auto enc_prod = enc_a * enc_b;
  std::size_t size_before = enc_prod.size();

  // Relinearize should reduce size
  auto enc_relin = enc_prod.relinearize(ctx, keys);
  std::size_t size_after = enc_relin.size();

  if(!enc_relin.isValid()) {
    std::cerr << "FAIL: relinearize() returned invalid result" << std::endl;
    return 1;
  }

  if(size_after > size_before) {
    std::cerr << "FAIL: size increased after relinearize (before="
              << size_before << ", after=" << size_after << ")" << std::endl;
    return 1;
  }

  // Result should still be correct
  std::int64_t result = enc_relin.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: result changed after relinearize: " << result
              << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS (size: " << size_before << " -> " << size_after << ")"
            << std::endl;
  return 0;
}
