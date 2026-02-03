/**
 * Homomorphic Addition Example
 *
 * This example demonstrates how to perform addition on encrypted data
 * without ever decrypting it. The computation happens entirely on
 * ciphertexts, and only the final result is decrypted.
 *
 * Uses the new SEALCrypt abstraction layer for a clean, simple API.
 */

#include <iostream>
#include <sealcrypt/sealcrypt.hpp>

auto main() -> int {
  std::cout << "=== Homomorphic Addition Example ===" << std::endl;
  std::cout << std::endl;

  // Step 1: Create a crypto context
  // SecurityLevel::Low is fast, SecurityLevel::High is more secure
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << std::endl;
    return 1;
  }
  std::cout << "Crypto context created." << std::endl;

  // Step 2: Generate a key pair
  sealcrypt::KeyPair keys(ctx);
  if(!keys.generate()) {
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return 1;
  }
  std::cout << "Keys generated." << std::endl;

  // Step 3: Define values to add
  std::int64_t value1 = 15;
  std::int64_t value2 = 27;

  std::cout << std::endl;
  std::cout << "Input values:" << std::endl;
  std::cout << "  Value 1: " << value1 << std::endl;
  std::cout << "  Value 2: " << value2 << std::endl;
  std::cout << "  Expected sum: " << (value1 + value2) << std::endl;
  std::cout << std::endl;

  // Step 4: Encrypt the values
  auto encrypted1 = sealcrypt::HomomorphicInt::encrypt(value1, ctx, keys);
  auto encrypted2 = sealcrypt::HomomorphicInt::encrypt(value2, ctx, keys);

  if(!encrypted1.isValid() || !encrypted2.isValid()) {
    std::cerr << "Encryption failed!" << std::endl;
    return 1;
  }
  std::cout << "Values encrypted." << std::endl;

  // Step 5: Perform homomorphic addition using operator+
  // This addition happens on ENCRYPTED data!
  auto encrypted_sum = encrypted1 + encrypted2;

  std::cout << "Homomorphic addition performed on encrypted data!" << std::endl;

  // Step 6: Decrypt the result
  std::int64_t result = encrypted_sum.decrypt(ctx, keys);

  std::cout << std::endl;
  std::cout << "=== Result ===" << std::endl;
  std::cout << "  Decrypted sum: " << result << std::endl;
  std::cout << "  Verification: " << value1 << " + " << value2 << " = "
            << result;

  if(result == value1 + value2) {
    std::cout << " [CORRECT]" << std::endl;
  } else {
    std::cout << " [ERROR]" << std::endl;
  }

  // Bonus: Demonstrate other operations
  std::cout << std::endl;
  std::cout << "=== Bonus: More Operations ===" << std::endl;

  // Add a plaintext value (more efficient than encrypting first)
  auto sum_plus_8 = encrypted_sum.addPlain(8, ctx);
  std::cout << "  (" << value1 << " + " << value2
            << ") + 8 = " << sum_plus_8.decrypt(ctx, keys) << std::endl;

  // Multiplication
  auto product = encrypted1 * encrypted2;
  std::cout << "  " << value1 << " * " << value2 << " = "
            << product.decrypt(ctx, keys) << std::endl;

  // Subtraction
  auto diff = encrypted2 - encrypted1;
  std::cout << "  " << value2 << " - " << value1 << " = "
            << diff.decrypt(ctx, keys) << std::endl;

  return 0;
}
