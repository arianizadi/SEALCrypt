#include "sealcrypt/encrypt.hpp"

#include <fstream>
#include <iterator>

namespace sealcrypt {

  Encryptor::Encryptor() = default;
  Encryptor::~Encryptor() = default;

  auto Encryptor::init(std::size_t poly_modulus_degree,
                       std::uint64_t plain_modulus) -> bool {
    try {
      return initializeContext(poly_modulus_degree, plain_modulus);
    } catch(const std::exception& e) {
      last_error_ = "Initialization failed: " + std::string(e.what());
      return false;
    }
  }

  auto Encryptor::initializeContext(std::size_t poly_modulus_degree,
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
        last_error_ = "Failed to set encryption parameters";
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      last_error_ = "Context initialization failed: " + std::string(e.what());
      return false;
    }
  }

  auto Encryptor::generateKeys(const std::string& public_key_path,
                               const std::string& private_key_path) -> bool {
    try {
      if(!context_) {
        last_error_ = "Context not initialized";
        return false;
      }

      keygen_ = std::make_unique< seal::KeyGenerator >(*context_);

      // Get public and secret key
      auto public_key = keygen_->create_public_key();
      auto secret_key = keygen_->secret_key();

      // Save public key
      std::ofstream public_key_file(public_key_path, std::ios::binary);
      public_key.save(public_key_file);

      // Save private key
      std::ofstream private_key_file(private_key_path, std::ios::binary);
      secret_key.save(private_key_file);

      return true;
    } catch(const std::exception& e) {
      last_error_ = "Key generation failed: " + std::string(e.what());
      return false;
    }
  }

  auto Encryptor::encryptFile(const std::string& input_path,
                              const std::string& output_path,
                              const std::string& public_key_path) -> bool {
    try {
      if(!context_) {
        last_error_ = "Context not initialized";
        return false;
      }

      // Read public key
      seal::PublicKey public_key;
      std::ifstream public_key_file(public_key_path, std::ios::binary);
      public_key.load(*context_, public_key_file);

      // Create encryptor
      encryptor_ = std::make_unique< seal::Encryptor >(*context_, public_key);

      // Read input file
      std::ifstream input_file(input_path, std::ios::binary);
      std::vector< std::uint8_t > input_data(
          (std::istreambuf_iterator< char >(input_file)),
          std::istreambuf_iterator< char >());

      // Prepare plaintexts
      auto plaintexts = preparePlaintexts(input_data);

      // Encrypt and save
      std::ofstream output_file(output_path, std::ios::binary);

      // Save number of ciphertexts first
      std::size_t count = plaintexts.size();
      output_file.write(reinterpret_cast< const char* >(&count), sizeof(count));

      // Encrypt and save each plaintext
      for(const auto& plaintext : plaintexts) {
        seal::Ciphertext ciphertext;
        encryptor_->encrypt(plaintext, ciphertext);
        ciphertext.save(output_file);
      }

      return true;
    } catch(const std::exception& e) {
      last_error_ = "Encryption failed: " + std::string(e.what());
      return false;
    }
  }

  auto Encryptor::preparePlaintexts(const std::vector< std::uint8_t >& data)
      -> std::vector< seal::Plaintext > {
    std::vector< seal::Plaintext > plaintexts;

    // Get batch size from context
    auto context_data = context_->first_context_data();
    auto plain_modulus = context_data->parms().plain_modulus();
    std::size_t batch_size = plain_modulus.value() - 1;

    // Process data in batches
    for(std::size_t i = 0; i < data.size(); i += batch_size) {
      std::vector< std::uint64_t > batch;
      for(std::size_t j = 0; j < batch_size && (i + j) < data.size(); ++j) {
        batch.push_back(static_cast< std::uint64_t >(data[i + j]));
      }

      // Create plaintext from batch
      seal::Plaintext plaintext;
      plaintext.resize(batch.size());
      for(std::size_t j = 0; j < batch.size(); ++j) {
        plaintext[j] = batch[j];
      }

      plaintexts.push_back(plaintext);
    }

    return plaintexts;
  }

  auto Encryptor::getLastError() const -> std::string {
    return last_error_;
  }

} // namespace sealcrypt