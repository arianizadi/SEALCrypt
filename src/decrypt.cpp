#include "sealcrypt/decrypt.hpp"

#include "sealcrypt/file_handler.hpp"

#include <sstream>

namespace sealcrypt {

  struct Decryptor::Impl {
    const CryptoContext& ctx;
    std::string last_error;

    explicit Impl(const CryptoContext& context) : ctx(context) {
    }

    auto processDecrypted(const std::vector< seal::Plaintext >& plaintexts,
                          std::size_t original_size)
        -> std::vector< std::uint8_t > {
      std::vector< std::uint8_t > result;
      result.reserve(original_size);

      // Process each plaintext
      for(const auto& plaintext : plaintexts) {
        for(std::size_t i = 0; i < plaintext.coeff_count(); ++i) {
          if(result.size() >= original_size) {
            break; // Stop at original size to avoid padding bytes
          }
          // Include ALL bytes, even zeros (this fixes the zero-byte bug)
          result.push_back(static_cast< std::uint8_t >(plaintext[i]));
        }
      }

      return result;
    }
  };

  Decryptor::Decryptor(const CryptoContext& ctx) :
      impl_(std::make_unique< Impl >(ctx)) {
  }

  Decryptor::~Decryptor() = default;

  Decryptor::Decryptor(Decryptor&&) noexcept = default;
  auto Decryptor::operator=(Decryptor&&) noexcept -> Decryptor& = default;

  auto Decryptor::decryptFile(const std::string& input_path,
                              const std::string& output_path,
                              const KeyPair& keys) -> bool {
    try {
      if(!impl_->ctx.isValid()) {
        impl_->last_error = "Invalid crypto context";
        return false;
      }

      if(!keys.hasSecretKey()) {
        impl_->last_error = "No secret key available";
        return false;
      }

      // Open encrypted file using FileHandler
      auto input_file
          = FileHandler::openForReading(input_path, impl_->last_error);
      if(!input_file) {
        return false;
      }

      // Read header: original data size
      std::size_t original_size = 0;
      input_file->read(reinterpret_cast< char* >(&original_size),
                       sizeof(original_size));

      // Read number of ciphertexts
      std::size_t ciphertext_count = 0;
      input_file->read(reinterpret_cast< char* >(&ciphertext_count),
                       sizeof(ciphertext_count));

      // Create SEAL decryptor
      seal::Decryptor decryptor(impl_->ctx.sealContext(), keys.secretKey());

      // Decrypt each ciphertext
      std::vector< seal::Plaintext > plaintexts;
      plaintexts.reserve(ciphertext_count);

      for(std::size_t i = 0; i < ciphertext_count; ++i) {
        seal::Ciphertext ciphertext;
        ciphertext.load(impl_->ctx.sealContext(), *input_file);

        seal::Plaintext plaintext;
        decryptor.decrypt(ciphertext, plaintext);
        plaintexts.push_back(std::move(plaintext));
      }

      // Process decrypted data with correct size
      auto decrypted_data = impl_->processDecrypted(plaintexts, original_size);

      // Write output file using FileHandler
      if(!FileHandler::writeFile(
             output_path, decrypted_data, impl_->last_error)) {
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      impl_->last_error = "Decryption failed: " + std::string(e.what());
      return false;
    }
  }

  auto Decryptor::decryptBytes(const std::vector< std::uint8_t >& data,
                               const KeyPair& keys)
      -> std::vector< std::uint8_t > {
    try {
      if(!impl_->ctx.isValid()) {
        impl_->last_error = "Invalid crypto context";
        return {};
      }

      if(!keys.hasSecretKey()) {
        impl_->last_error = "No secret key available";
        return {};
      }

      std::istringstream iss(std::string(data.begin(), data.end()),
                             std::ios::binary);

      // Read original size
      std::size_t original_size = 0;
      iss.read(reinterpret_cast< char* >(&original_size),
               sizeof(original_size));

      // Read count
      std::size_t ciphertext_count = 0;
      iss.read(reinterpret_cast< char* >(&ciphertext_count),
               sizeof(ciphertext_count));

      seal::Decryptor decryptor(impl_->ctx.sealContext(), keys.secretKey());

      std::vector< seal::Plaintext > plaintexts;
      for(std::size_t i = 0; i < ciphertext_count; ++i) {
        seal::Ciphertext ciphertext;
        ciphertext.load(impl_->ctx.sealContext(), iss);

        seal::Plaintext plaintext;
        decryptor.decrypt(ciphertext, plaintext);
        plaintexts.push_back(std::move(plaintext));
      }

      return impl_->processDecrypted(plaintexts, original_size);
    } catch(const std::exception& e) {
      impl_->last_error = "Decryption failed: " + std::string(e.what());
      return {};
    }
  }

  auto Decryptor::getLastError() const -> std::string {
    return impl_->last_error;
  }

} // namespace sealcrypt
