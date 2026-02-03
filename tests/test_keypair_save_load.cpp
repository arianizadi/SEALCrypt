// Test: KeyPair::save() and load()

#include "sealcrypt/sealcrypt.hpp"

#include <cstdio>
#include <iostream>

auto main() -> int {
  std::cout << "Test: KeyPair::save() and load()" << std::endl;

  const char* pub_path = "test_pub.key";
  const char* sec_path = "test_sec.key";

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);

  // Generate and save
  {
    sealcrypt::KeyPair keys(ctx);
    if(!keys.generate()) {
      std::cerr << "FAIL: generate() failed" << std::endl;
      return 1;
    }

    if(!keys.save(pub_path, sec_path)) {
      std::cerr << "FAIL: save() returned false" << std::endl;
      std::cerr << "Error: " << keys.getLastError() << std::endl;
      return 1;
    }
  }

  // Load into new KeyPair
  {
    sealcrypt::KeyPair keys(ctx);

    if(!keys.load(pub_path, sec_path)) {
      std::cerr << "FAIL: load() returned false" << std::endl;
      std::cerr << "Error: " << keys.getLastError() << std::endl;
      remove(pub_path);
      remove(sec_path);
      return 1;
    }

    if(!keys.hasPublicKey()) {
      std::cerr << "FAIL: hasPublicKey() false after load()" << std::endl;
      remove(pub_path);
      remove(sec_path);
      return 1;
    }
    if(!keys.hasSecretKey()) {
      std::cerr << "FAIL: hasSecretKey() false after load()" << std::endl;
      remove(pub_path);
      remove(sec_path);
      return 1;
    }
  }

  remove(pub_path);
  remove(sec_path);
  std::cout << "PASS" << std::endl;
  return 0;
}
