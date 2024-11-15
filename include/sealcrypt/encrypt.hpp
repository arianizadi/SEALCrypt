#pragma once

#include <memory>
#include <seal/seal.h>
#include <string>
#include <vector>

namespace sealcrypt {

  class Encryptor {
  public:
    Encryptor();
    ~Encryptor();

    // Initialize encryption parameters
    bool init(std::size_t poly_modulus_degree = 8192,
              std::uint64_t plain_modulus = 1024);

    // Encrypt a file using provided public key
    bool encryptFile(const std::string& input_path,
                     const std::string& output_path,
                     const std::string& public_key_path);

    // Generate new key pair
    bool generateKeys(const std::string& public_key_path,
                      const std::string& private_key_path);

    // Get last error message
    std::string getLastError() const;

  private:
    std::unique_ptr< seal::SEALContext > context_;
    std::unique_ptr< seal::KeyGenerator > keygen_;
    std::unique_ptr< seal::Encryptor > encryptor_;
    std::string last_error_;

    bool initializeContext(std::size_t poly_modulus_degree,
                           std::uint64_t plain_modulus);
    std::vector< seal::Plaintext >
    preparePlaintexts(const std::vector< std::uint8_t >& data);
  };
} // namespace sealcrypt