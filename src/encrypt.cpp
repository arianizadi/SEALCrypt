#include "sealcrypt/encrypt.hpp"

#include "sealcrypt/file_handler.hpp"

#include <sstream>

namespace sealcrypt {

  struct Encryptor::Impl {
    const CryptoContext& ctx;
    std::string last_error;

    explicit Impl(const CryptoContext& context) : ctx(context) {
    }

    auto preparePlaintexts(const std::vector< std::uint8_t >& data)
        -> std::vector< seal::Plaintext > {
      std::vector< seal::Plaintext > plaintexts;

      // Use a reasonable batch size based on plain modulus
      // Each byte is stored as one coefficient
      const std::size_t batch_size = 1024;

      for(std::size_t i = 0; i < data.size(); i += batch_size) {
        seal::Plaintext plaintext;
        std::size_t current_batch = std::min(batch_size, data.size() - i);
        plaintext.resize(current_batch);

        for(std::size_t j = 0; j < current_batch; ++j) {
          plaintext[j] = static_cast< std::uint64_t >(data[i + j]);
        }

        plaintexts.push_back(std::move(plaintext));
      }

      return plaintexts;
    }
  };

  Encryptor::Encryptor(const CryptoContext& ctx) :
      impl_(std::make_unique< Impl >(ctx)) {
  }

  Encryptor::~Encryptor() = default;

  Encryptor::Encryptor(Encryptor&&) noexcept = default;
  auto Encryptor::operator=(Encryptor&&) noexcept -> Encryptor& = default;

  auto Encryptor::encryptFile(const std::string& input_path,
                              const std::string& output_path,
                              const KeyPair& keys) -> bool {
    try {
      if(!impl_->ctx.isValid()) {
        impl_->last_error = "Invalid crypto context";
        return false;
      }

      if(!keys.hasPublicKey()) {
        impl_->last_error = "No public key available";
        return false;
      }

      // Read input file using FileHandler
      std::vector< std::uint8_t > input_data;
      if(!FileHandler::readFile(input_path, input_data, impl_->last_error)) {
        return false;
      }

      // Create SEAL encryptor
      seal::Encryptor encryptor(impl_->ctx.sealContext(), keys.publicKey());

      // Prepare plaintexts
      auto plaintexts = impl_->preparePlaintexts(input_data);

      // Open output file using FileHandler
      auto output_file
          = FileHandler::openForWriting(output_path, impl_->last_error);
      if(!output_file) {
        return false;
      }

      // Write header: original data size (for correct decryption)
      std::size_t original_size = input_data.size();
      output_file->write(reinterpret_cast< const char* >(&original_size),
                         sizeof(original_size));

      // Write number of ciphertexts
      std::size_t count = plaintexts.size();
      output_file->write(reinterpret_cast< const char* >(&count),
                         sizeof(count));

      // Encrypt and save each plaintext
      for(const auto& plaintext : plaintexts) {
        seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);
        ciphertext.save(*output_file);
      }

      return true;
    } catch(const std::exception& e) {
      impl_->last_error = "Encryption failed: " + std::string(e.what());
      return false;
    }
  }

  auto Encryptor::encryptBytes(const std::vector< std::uint8_t >& data,
                               const KeyPair& keys)
      -> std::vector< std::uint8_t > {
    try {
      if(!impl_->ctx.isValid()) {
        impl_->last_error = "Invalid crypto context";
        return {};
      }

      if(!keys.hasPublicKey()) {
        impl_->last_error = "No public key available";
        return {};
      }

      seal::Encryptor encryptor(impl_->ctx.sealContext(), keys.publicKey());
      auto plaintexts = impl_->preparePlaintexts(data);

      // Serialize to bytes
      std::ostringstream oss(std::ios::binary);

      // Write original size
      std::size_t original_size = data.size();
      oss.write(reinterpret_cast< const char* >(&original_size),
                sizeof(original_size));

      // Write count
      std::size_t count = plaintexts.size();
      oss.write(reinterpret_cast< const char* >(&count), sizeof(count));

      // Encrypt each plaintext
      for(const auto& plaintext : plaintexts) {
        seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);
        ciphertext.save(oss);
      }

      std::string str = oss.str();
      return std::vector< std::uint8_t >(str.begin(), str.end());
    } catch(const std::exception& e) {
      impl_->last_error = "Encryption failed: " + std::string(e.what());
      return {};
    }
  }

  auto Encryptor::getLastError() const -> std::string {
    return impl_->last_error;
  }

} // namespace sealcrypt
