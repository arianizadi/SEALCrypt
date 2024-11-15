#pragma once

#include <memory>
#include <seal/seal.h>
#include <string>
#include <vector>

namespace sealcrypt {

  class Decryptor {
  public:
    Decryptor();
    ~Decryptor();

    // Initialize decryption with parameters
    auto init(std::size_t poly_modulus_degree = 8192,
              std::uint64_t plain_modulus = 1024) -> bool;

    // Decrypt a file using provided private key
    auto decryptFile(const std::string &input_path,
                     const std::string &output_path,
                     const std::string &private_key_path) -> bool;

    // Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

  private:
    std::unique_ptr< seal::SEALContext > context_;
    std::unique_ptr< seal::Decryptor > decryptor_;
    std::string last_error_;

    auto initializeContext(std::size_t poly_modulus_degree,
                           std::uint64_t plain_modulus) -> bool;
    auto processDecrypted(const std::vector< seal::Plaintext > &plaintexts)
        -> std::vector< std::uint8_t >;
  };
} // namespace sealcrypt