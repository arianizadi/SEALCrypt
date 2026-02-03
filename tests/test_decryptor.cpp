#include "sealcrypt/sealcrypt.hpp"

#include <cstring>
#include <fstream>
#include <iostream>

auto testBasicDecryption() -> bool {
  // Create test file with known content
  const std::string original_content = "Hello, SEALCrypt!";
  {
    std::ofstream test_file("test_input.txt");
    test_file << original_content;
  }

  // Setup context and keys
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

  // Encrypt
  sealcrypt::Encryptor encryptor(ctx);
  if(!encryptor.encryptFile("test_input.txt", "test_encrypted.dat", keys)) {
    std::cerr << "Error: " << encryptor.getLastError() << std::endl;
    return false;
  }

  // Decrypt
  sealcrypt::Decryptor decryptor(ctx);
  if(!decryptor.decryptFile("test_encrypted.dat", "test_decrypted.txt", keys)) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  // Verify content matches
  std::ifstream decrypted_file("test_decrypted.txt");
  std::string decrypted_content(
      (std::istreambuf_iterator< char >(decrypted_file)),
      std::istreambuf_iterator< char >());

  if(decrypted_content != original_content) {
    std::cerr << "Content mismatch!" << std::endl;
    std::cerr << "Original:  '" << original_content << "'" << std::endl;
    std::cerr << "Decrypted: '" << decrypted_content << "'" << std::endl;
    return false;
  }

  return true;
}

auto testZeroByteHandling() -> bool {
  // Create test file with zero bytes (this was a bug before)
  const std::vector< char > original_data = {'A', '\0', 'B', '\0', 'C'};
  {
    std::ofstream test_file("test_binary.bin", std::ios::binary);
    test_file.write(original_data.data(), original_data.size());
  }

  // Setup context and keys
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);
  keys.generate();

  // Encrypt
  sealcrypt::Encryptor encryptor(ctx);
  if(!encryptor.encryptFile("test_binary.bin", "test_binary.enc", keys)) {
    std::cerr << "Error: " << encryptor.getLastError() << std::endl;
    return false;
  }

  // Decrypt
  sealcrypt::Decryptor decryptor(ctx);
  if(!decryptor.decryptFile("test_binary.enc", "test_binary_dec.bin", keys)) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  // Read decrypted file
  std::ifstream decrypted_file("test_binary_dec.bin", std::ios::binary);
  std::vector< char > decrypted_data(
      (std::istreambuf_iterator< char >(decrypted_file)),
      std::istreambuf_iterator< char >());

  // Verify content matches (including zero bytes)
  if(decrypted_data.size() != original_data.size()) {
    std::cerr << "Size mismatch! Original: " << original_data.size()
              << ", Decrypted: " << decrypted_data.size() << std::endl;
    return false;
  }

  if(std::memcmp(
         decrypted_data.data(), original_data.data(), original_data.size())
     != 0) {
    std::cerr << "Binary content mismatch!" << std::endl;
    return false;
  }

  return true;
}

auto testKeyLoadSave() -> bool {
  // Generate and save keys
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys1(ctx);
  keys1.generate();
  keys1.save("test_pub.key", "test_priv.key");

  // Create test file
  const std::string original = "Test with loaded keys";
  {
    std::ofstream f("test_load.txt");
    f << original;
  }

  // Encrypt with original keys
  sealcrypt::Encryptor encryptor(ctx);
  encryptor.encryptFile("test_load.txt", "test_load.enc", keys1);

  // Load keys into new KeyPair and decrypt
  sealcrypt::KeyPair keys2(ctx);
  if(!keys2.load("test_pub.key", "test_priv.key")) {
    std::cerr << "Error loading keys: " << keys2.getLastError() << std::endl;
    return false;
  }

  sealcrypt::Decryptor decryptor(ctx);
  if(!decryptor.decryptFile("test_load.enc", "test_load_dec.txt", keys2)) {
    std::cerr << "Error: " << decryptor.getLastError() << std::endl;
    return false;
  }

  // Verify
  std::ifstream f("test_load_dec.txt");
  std::string decrypted((std::istreambuf_iterator< char >(f)),
                        std::istreambuf_iterator< char >());

  return decrypted == original;
}

auto main() -> int {
  bool all_passed = true;

  std::cout << "Testing basic decryption... ";
  if(testBasicDecryption()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing zero-byte handling... ";
  if(testZeroByteHandling()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  std::cout << "Testing key load/save... ";
  if(testKeyLoadSave()) {
    std::cout << "passed" << std::endl;
  } else {
    std::cout << "failed" << std::endl;
    all_passed = false;
  }

  // Cleanup
  remove("test_input.txt");
  remove("test_encrypted.dat");
  remove("test_decrypted.txt");
  remove("test_binary.bin");
  remove("test_binary.enc");
  remove("test_binary_dec.bin");
  remove("test_pub.key");
  remove("test_priv.key");
  remove("test_load.txt");
  remove("test_load.enc");
  remove("test_load_dec.txt");

  return all_passed ? 0 : 1;
}
