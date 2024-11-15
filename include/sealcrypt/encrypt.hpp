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
    auto init(std::size_t poly_modulus_degree = 8192,
              std::uint64_t plain_modulus = 1024) -> bool;

    // Encrypt a file using provided public key
    auto encryptFile(const std::string& input_path,
                     const std::string& output_path,
                     const std::string& public_key_path) -> bool;

    // Generate new key pair
    auto generateKeys(const std::string& public_key_path,
                      const std::string& private_key_path) -> bool;

    // Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

  private:
    std::unique_ptr< seal::SEALContext > context_;
    std::unique_ptr< seal::KeyGenerator > keygen_;
    std::unique_ptr< seal::Encryptor > encryptor_;
    std::string last_error_;

    auto initializeContext(std::size_t poly_modulus_degree,
                           std::uint64_t plain_modulus) -> bool;
    auto preparePlaintexts(const std::vector< std::uint8_t >& data)
        -> std::vector< seal::Plaintext >;
  };
} // namespace sealcrypt