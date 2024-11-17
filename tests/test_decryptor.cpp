#include "sealcrypt/decrypt.hpp"
#include "sealcrypt/encrypt.hpp"

#include <fstream>
#include <iostream>
#include <string>

auto testDecryptorInitialization() -> bool {
  sealcrypt::Decryptor decryptor;
  if(!decryptor.init()) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }
  return true;
}

auto testFileDecryption() -> bool {
  const std::string test_message
      = "This is a test message for encryption and decryption.";

  // Create test file
  {
    std::ofstream test_file("test_input.txt");
    test_file << test_message;
  }

  // First encrypt
  {
    sealcrypt::Encryptor encryptor;
    if(!encryptor.init()
       || !encryptor.generateKeys("test_public.key", "test_private.key")
       || !encryptor.encryptFile(
           "test_input.txt", "test_encrypted.dat", "test_public.key")) {
      std::cerr << "Error in encryption setup: " << encryptor.getLastError()
                << std::endl;
      return false;
    }
  }

  // Then decrypt
  sealcrypt::Decryptor decryptor;
  if(!decryptor.init()) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  if(!decryptor.decryptFile(
         "test_encrypted.dat", "test_decrypted.txt", "test_private.key")) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  // Verify decrypted content matches original
  std::ifstream decrypted_file("test_decrypted.txt");
  std::string decrypted_content;
  std::getline(decrypted_file, decrypted_content);

  return decrypted_content == test_message;
}

auto testInvalidKeyDecryption() -> bool {
  sealcrypt::Decryptor decryptor;
  if(!decryptor.init()) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  // Try to decrypt with non-existent key
  bool should_fail = decryptor.decryptFile(
      "test_encrypted.dat", "test_decrypted.txt", "nonexistent_key.key");

  // Test should pass if decryption fails (as expected)
  return !should_fail;
}

auto main() -> int {
  bool all_passed = true;

  std::cout << "Testing Decryptor initialization... ";
  if(testDecryptorInitialization()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing file decryption... ";
  if(testFileDecryption()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing invalid key decryption... ";
  if(testInvalidKeyDecryption()) {
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
  remove("test_decrypted.txt");

  return all_passed ? 0 : 1;
}