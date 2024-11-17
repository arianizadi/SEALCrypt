#include "sealcrypt/decrypt.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace sealcrypt {

  Decryptor::Decryptor() = default;
  Decryptor::~Decryptor() = default;

  auto Decryptor::init(std::size_t poly_modulus_degree,
                       std::uint64_t plain_modulus) -> bool {
    try {
      return initializeContext(poly_modulus_degree, plain_modulus);
    } catch(const std::exception& e) {
      last_error_ = "Initialization failed: " + std::string(e.what());
      return false;
    }
  }

  auto Decryptor::initializeContext(std::size_t poly_modulus_degree,
                                    std::uint64_t plain_modulus) -> bool {
    try {
      seal::EncryptionParameters params(seal::scheme_type::bfv);
      params.set_poly_modulus_degree(poly_modulus_degree);
      params.set_plain_modulus(plain_modulus);

      // Set coefficient modulus
      params.set_coeff_modulus(
          seal::CoeffModulus::BFVDefault(poly_modulus_degree));

      context_ = std::make_unique< seal::SEALContext >(params);

      if(!context_->parameters_set()) {
        last_error_ = "Failed to set decryption parameters";
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      last_error_ = "Context initialization failed: " + std::string(e.what());
      return false;
    }
  }

  auto Decryptor::decryptFile(const std::string& input_path,
                              const std::string& output_path,
                              const std::string& private_key_path) -> bool {
    try {
      if(!context_) {
        last_error_ = "Context not initialized";
        return false;
      }

      // Read private key
      seal::SecretKey secret_key;
      std::ifstream private_key_file(private_key_path, std::ios::binary);
      secret_key.load(*context_, private_key_file);

      // Create decryptor
      decryptor_ = std::make_unique< seal::Decryptor >(*context_, secret_key);

      // Open encrypted file
      std::ifstream input_file(input_path, std::ios::binary);

      // Read number of ciphertexts
      std::size_t ciphertext_count;
      input_file.read(reinterpret_cast< char* >(&ciphertext_count),
                      sizeof(ciphertext_count));

      // Decrypt each ciphertext
      std::vector< seal::Plaintext > plaintexts;
      for(std::size_t i = 0; i < ciphertext_count; ++i) {
        seal::Ciphertext ciphertext;
        ciphertext.load(*context_, input_file);

        seal::Plaintext plaintext;
        decryptor_->decrypt(ciphertext, plaintext);
        plaintexts.push_back(plaintext);
      }

      // Process decrypted data
      auto decrypted_data = processDecrypted(plaintexts);

      // Save decrypted data
      std::ofstream output_file(output_path, std::ios::binary);
      output_file.write(reinterpret_cast< const char* >(decrypted_data.data()),
                        decrypted_data.size());

      return true;
    } catch(const std::exception& e) {
      last_error_ = "Decryption failed: " + std::string(e.what());
      return false;
    }
  }

  auto
  Decryptor::processDecrypted(const std::vector< seal::Plaintext >& plaintexts)
      -> std::vector< std::uint8_t > {
    std::vector< std::uint8_t > result;

    // Process each plaintext
    for(const auto& plaintext : plaintexts) {
      // Convert each coefficient back to original byte
      for(std::size_t i = 0; i < plaintext.coeff_count(); ++i) {
        auto value = plaintext[i];
        // Only process non-zero values to handle padding
        if(value != 0) {
          result.push_back(static_cast< std::uint8_t >(value));
        }
      }
    }

    return result;
  }

  auto Decryptor::getLastError() const -> std::string {
    return last_error_;
  }

} // namespace sealcrypt