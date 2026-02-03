#include "sealcrypt/sealcrypt.hpp"

#include <fstream>
#include <iostream>

auto testContextInitialization() -> bool {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << std::endl;
    return false;
  }
  return true;
}

auto testKeyGeneration() -> bool {
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << std::endl;
    return false;
  }

  sealcrypt::KeyPair keys(ctx);
  if(!keys.generate()) {
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return false;
  }

  if(!keys.save("test_public.key", "test_private.key")) {
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return false;
  }

  // Verify key files exist
  std::ifstream pub_key("test_public.key");
  std::ifstream priv_key("test_private.key");
  if(!pub_key.good() || !priv_key.good()) {
    return false;
  }

  return true;
}

auto testFileEncryption() -> bool {
  // Create test file
  {
    std::ofstream test_file("test_input.txt");
    test_file << "This is a test message for encryption.";
  }

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << std::endl;
    return false;
  }

  sealcrypt::KeyPair keys(ctx);
  if(!keys.generate()) {
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return false;
  }

  if(!keys.save("test_public.key", "test_private.key")) {
    std::cerr << "Error: " << keys.getLastError() << std::endl;
    return false;
  }

  sealcrypt::Encryptor encryptor(ctx);
  if(!encryptor.encryptFile("test_input.txt", "test_encrypted.dat", keys)) {
    std::cerr << "Error: " << encryptor.getLastError() << std::endl;
    return false;
  }

  // Verify encrypted file exists and has content
  std::ifstream encrypted_file("test_encrypted.dat", std::ios::binary);
  if(!encrypted_file.good()) {
    return false;
  }

  encrypted_file.seekg(0, std::ios::end);
  if(encrypted_file.tellg() == 0) {
    return false;
  }

  return true;
}

auto main() -> int {
  bool all_passed = true;

  std::cout << "Testing context initialization... ";
  if(testContextInitialization()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing key generation... ";
  if(testKeyGeneration()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing file encryption... ";
  if(testFileEncryption()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  // Cleanup test files
  remove("test_input.txt");
  remove("test_public.key");
  remove("test_private.key");
  remove("test_encrypted.dat");

  return all_passed ? 0 : 1;
}
