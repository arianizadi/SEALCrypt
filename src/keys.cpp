#include "sealcrypt/keys.hpp"

#include "sealcrypt/file_handler.hpp"

#include <exception>
#include <memory>
#include <seal/galoiskeys.h>
#include <seal/keygenerator.h>
#include <seal/publickey.h>
#include <seal/relinkeys.h>
#include <seal/secretkey.h>
#include <stdexcept>
#include <string>

namespace sealcrypt {

  struct KeyPair::Impl {
    const CryptoContext& ctx;
    std::unique_ptr< seal::KeyGenerator > keygen;
    std::unique_ptr< seal::PublicKey > public_key;
    std::unique_ptr< seal::SecretKey > secret_key;
    std::unique_ptr< seal::RelinKeys > relin_keys;
    std::unique_ptr< seal::GaloisKeys > galois_keys;
    mutable std::string last_error;

    explicit Impl(const CryptoContext& context) : ctx(context) {
    }
  };

  // ==================== Constructors / Destructor ====================

  KeyPair::KeyPair(const CryptoContext& ctx) :
      impl_(std::make_unique< Impl >(ctx)) {
  }

  KeyPair::~KeyPair() = default;

  KeyPair::KeyPair(KeyPair&&) noexcept = default;

  auto KeyPair::operator=(KeyPair&&) noexcept -> KeyPair& = default;

  // ==================== Key Generation ====================

  auto KeyPair::generate() -> bool {
    try {
      if(!impl_->ctx.isValid()) {
        impl_->last_error = "Invalid Context";
        return false;
      }
      impl_->keygen
          = std::make_unique< seal::KeyGenerator >(impl_->ctx.sealContext());
      impl_->secret_key
          = std::make_unique< seal::SecretKey >(impl_->keygen->secret_key());
      impl_->public_key = std::make_unique< seal::PublicKey >();
      impl_->keygen->create_public_key(*impl_->public_key);
    } catch(const std::exception& e) {
      impl_->last_error = "Keygen Failed: " + std::string(e.what());
      return false;
    }
    return true;
  }

  // when should you use this ?
  // relinearization keys are used when the polynomial is too large
  // +, -     -> will stay 2 polynomial
  // *        -> increases polynomial by 1
  // power()  -> increases by n power
  // we want 2 polynomial so we relinearize, making 3 -> 2
  auto KeyPair::generateRelinKeys() -> bool {
    try {
      if(!impl_->keygen) {
        impl_->last_error = "Generate Not Called";
        return false;
      }
      impl_->relin_keys = std::make_unique< seal::RelinKeys >();
      impl_->keygen->create_relin_keys(*impl_->relin_keys);

    } catch(const std::exception& e) {
      impl_->last_error = "Relin Keygen Failed: " + std::string(e.what());
      return false;
    }
    return true;
  }

  // when should you use this ?
  // galois keys are used when trying to calc batched data like a vector
  // hint hint - grouping of vectors is a matrix
  // hint hint hint - ML uses matrices ;)
  auto KeyPair::generateGaloisKeys() -> bool {
    try {
      if(!impl_->keygen) {
        impl_->last_error = "Generate Not Called";
        return false;
      }
      impl_->galois_keys = std::make_unique< seal::GaloisKeys >();
      impl_->keygen->create_galois_keys(*impl_->galois_keys);

    } catch(const std::exception& e) {
      impl_->last_error = "Galois Keygen Failed: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::generateAll() -> bool {
    if(!generate()) {
      return false;
    }
    if(!generateRelinKeys()) {
      return false;
    }
    if(!generateGaloisKeys()) {
      return false;
    }
    return true;
  }

  // ==================== Save Keys ====================

  auto KeyPair::save(const std::string& public_key_path,
                     const std::string& secret_key_path) const -> bool {
    if(!savePublicKey(public_key_path)) {
      impl_->last_error = "Error saving public key";
      return false;
    }

    if(!saveSecretKey(secret_key_path)) {
      impl_->last_error = "Error saving private key";
      return false;
    }

    return true;
  }
  auto KeyPair::savePublicKey(const std::string& path) const -> bool {
    if(!impl_->public_key) {
      impl_->last_error = "No public key to save";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForWriting(path, error);
    if(!file) {
      impl_->last_error = "Failed to open file for writing: " + error;
      return false;
    }

    try {
      impl_->public_key->save(*file);
      if(!*file) {
        impl_->last_error = "Error writing public key to file: " + path;
        return false;
      }
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while saving public key: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::saveSecretKey(const std::string& path) const -> bool {
    if(!impl_->secret_key) {
      impl_->last_error = "No secret key to save";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForWriting(path, error);
    if(!file) {
      impl_->last_error = "Failed to open file for writing: " + error;
      return false;
    }

    try {
      impl_->secret_key->save(*file);
      if(!*file) {
        impl_->last_error = "Error writing secret key to file: " + path;
        return false;
      }
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while saving secret key: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::saveRelinKeys(const std::string& path) const -> bool {
    if(!impl_->relin_keys) {
      impl_->last_error = "No relin keys to save";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForWriting(path, error);
    if(!file) {
      impl_->last_error = "Failed to open file for writing: " + error;
      return false;
    }

    try {
      impl_->relin_keys->save(*file);
      if(!*file) {
        impl_->last_error = "Error writing relin keys to file: " + path;
        return false;
      }
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while saving relin keys: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::saveGaloisKeys(const std::string& path) const -> bool {
    if(!impl_->galois_keys) {
      impl_->last_error = "No Galois keys to save";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForWriting(path, error);
    if(!file) {
      impl_->last_error = "Failed to open file for writing: " + error;
      return false;
    }

    try {
      impl_->galois_keys->save(*file);
      if(!*file) {
        impl_->last_error = "Error writing Galois keys to file: " + path;
        return false;
      }
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while saving Galois keys: " + std::string(e.what());
      return false;
    }
    return true;
  }

  // ==================== Load Keys ====================

  auto KeyPair::load(const std::string& public_key_path,
                     const std::string& secret_key_path) -> bool {
    // Load both public and secret keys
    return loadPublicKey(public_key_path) && loadSecretKey(secret_key_path);
  }

  auto KeyPair::loadPublicKey(const std::string& path) -> bool {
    if(!impl_->ctx.isValid()) {
      impl_->last_error = "Invalid context";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForReading(path, error);
    if(!file) {
      impl_->last_error
          = "Failed to open public key file for reading: " + error;
      return false;
    }

    try {
      auto pk = std::make_unique< seal::PublicKey >();
      pk->load(impl_->ctx.sealContext(), *file);
      if(!*file) {
        impl_->last_error = "Error reading public key from file: " + path;
        return false;
      }
      impl_->public_key = std::move(pk);
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while loading public key: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::loadSecretKey(const std::string& path) -> bool {
    if(!impl_->ctx.isValid()) {
      impl_->last_error = "Invalid context";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForReading(path, error);
    if(!file) {
      impl_->last_error
          = "Failed to open secret key file for reading: " + error;
      return false;
    }

    try {
      auto sk = std::make_unique< seal::SecretKey >();
      sk->load(impl_->ctx.sealContext(), *file);
      if(!*file) {
        impl_->last_error = "Error reading secret key from file: " + path;
        return false;
      }
      impl_->secret_key = std::move(sk);
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while loading secret key: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::loadRelinKeys(const std::string& path) -> bool {
    if(!impl_->ctx.isValid()) {
      impl_->last_error = "Invalid context";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForReading(path, error);
    if(!file) {
      impl_->last_error
          = "Failed to open relin keys file for reading: " + error;
      return false;
    }

    try {
      auto rk = std::make_unique< seal::RelinKeys >();
      rk->load(impl_->ctx.sealContext(), *file);
      if(!*file) {
        impl_->last_error = "Error reading relin keys from file: " + path;
        return false;
      }
      impl_->relin_keys = std::move(rk);
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while loading relin keys: " + std::string(e.what());
      return false;
    }
    return true;
  }

  auto KeyPair::loadGaloisKeys(const std::string& path) -> bool {
    if(!impl_->ctx.isValid()) {
      impl_->last_error = "Invalid context";
      return false;
    }

    std::string error;
    auto file = FileHandler::openForReading(path, error);
    if(!file) {
      impl_->last_error
          = "Failed to open Galois keys file for reading: " + error;
      return false;
    }

    try {
      auto gk = std::make_unique< seal::GaloisKeys >();
      gk->load(impl_->ctx.sealContext(), *file);
      if(!*file) {
        impl_->last_error = "Error reading Galois keys from file: " + path;
        return false;
      }
      impl_->galois_keys = std::move(gk);
    } catch(const std::exception& e) {
      impl_->last_error
          = "Exception while loading Galois keys: " + std::string(e.what());
      return false;
    }
    return true;
  }

  // ==================== Key Availability Checks ====================

  auto KeyPair::hasPublicKey() const -> bool {
    return impl_->public_key != nullptr;
  }

  auto KeyPair::hasSecretKey() const -> bool {
    return impl_->secret_key != nullptr;
  }

  auto KeyPair::hasRelinKeys() const -> bool {
    return impl_->relin_keys != nullptr;
  }

  auto KeyPair::hasGaloisKeys() const -> bool {
    return impl_->galois_keys != nullptr;
  }

  // ==================== Key Access ====================

  auto KeyPair::publicKey() const -> const seal::PublicKey& {
    if(!impl_->public_key) {
      throw std::runtime_error("Public key not available");
    }
    return *impl_->public_key;
  }

  auto KeyPair::secretKey() const -> const seal::SecretKey& {
    if(!impl_->secret_key) {
      throw std::runtime_error("Secret key not available");
    }
    return *impl_->secret_key;
  }

  auto KeyPair::relinKeys() const -> const seal::RelinKeys& {
    if(!impl_->relin_keys) {
      throw std::runtime_error("Relin keys not available");
    }
    return *impl_->relin_keys;
  }

  auto KeyPair::galoisKeys() const -> const seal::GaloisKeys& {
    if(!impl_->galois_keys) {
      throw std::runtime_error("Galois keys not available");
    }
    return *impl_->galois_keys;
  }

  // ==================== Error Handling ====================

  auto KeyPair::getLastError() const -> std::string {
    return impl_->last_error;
  }

} // namespace sealcrypt
