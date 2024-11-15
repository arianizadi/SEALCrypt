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
    bool init(std::size_t poly_modulus_degree = 8192,
              std::uint64_t plain_modulus = 1024);

    // Decrypt a file using provided private key
    bool decryptFile(const std::string &input_path,
                     const std::string &output_path,
                     const std::string &private_key_path);

    // Get last error message
    std::string getLastError() const;

  private:
    std::unique_ptr< seal::SEALContext > context_;
    std::unique_ptr< seal::Decryptor > decryptor_;
    std::string last_error_;

    bool initializeContext(std::size_t poly_modulus_degree,
                           std::uint64_t plain_modulus);
    std::vector< std::uint8_t >
    processDecrypted(const std::vector< seal::Plaintext > &plaintexts);
  };
} // namespace sealcrypt