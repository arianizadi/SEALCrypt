#pragma once

#include "sealcrypt/context.hpp"

#include <memory>
#include <seal/seal.h>
#include <string>

namespace sealcrypt {

  /// KeyPair manages all keys for homomorphic encryption operations.
  /// Includes public key, secret key, relinearization keys, and Galois keys.
  class KeyPair {
  public:
    /// Create a KeyPair associated with a CryptoContext
    /// @param ctx The crypto context (must outlive this KeyPair)
    explicit KeyPair(const CryptoContext& ctx);

    ~KeyPair();

    // Non-copyable, movable
    KeyPair(const KeyPair&) = delete;
    auto operator=(const KeyPair&) -> KeyPair& = delete;
    KeyPair(KeyPair&&) noexcept;
    auto operator=(KeyPair&&) noexcept -> KeyPair&;

    // ==================== Key Generation ====================

    /// Generate a new key pair (public + secret keys)
    /// @return true if successful
    auto generate() -> bool;

    /// Generate relinearization keys (needed for multiplication)
    /// Must call generate() first
    /// @return true if successful
    auto generateRelinKeys() -> bool;

    /// Generate Galois keys (needed for rotation operations)
    /// Must call generate() first
    /// @return true if successful
    auto generateGaloisKeys() -> bool;

    /// Generate all keys at once (public, secret, relin, galois)
    /// @return true if successful
    auto generateAll() -> bool;

    // ==================== Save Keys ====================

    /// Save public and secret keys to files
    auto save(const std::string& public_key_path,
              const std::string& secret_key_path) const -> bool;

    /// Save only the public key
    auto savePublicKey(const std::string& path) const -> bool;

    /// Save only the secret key
    auto saveSecretKey(const std::string& path) const -> bool;

    /// Save relinearization keys
    auto saveRelinKeys(const std::string& path) const -> bool;

    /// Save Galois keys
    auto saveGaloisKeys(const std::string& path) const -> bool;

    // ==================== Load Keys ====================

    /// Load public and secret keys from files
    auto load(const std::string& public_key_path,
              const std::string& secret_key_path) -> bool;

    /// Load only the public key
    auto loadPublicKey(const std::string& path) -> bool;

    /// Load only the secret key
    auto loadSecretKey(const std::string& path) -> bool;

    /// Load relinearization keys
    auto loadRelinKeys(const std::string& path) -> bool;

    /// Load Galois keys
    auto loadGaloisKeys(const std::string& path) -> bool;

    // ==================== Key Availability Checks ====================

    /// Check if public key is available
    [[nodiscard]] auto hasPublicKey() const -> bool;

    /// Check if secret key is available
    [[nodiscard]] auto hasSecretKey() const -> bool;

    /// Check if relinearization keys are available
    [[nodiscard]] auto hasRelinKeys() const -> bool;

    /// Check if Galois keys are available
    [[nodiscard]] auto hasGaloisKeys() const -> bool;

    // ==================== Key Access ====================

    /// Get the public key (throws if not available)
    [[nodiscard]] auto publicKey() const -> const seal::PublicKey&;

    /// Get the secret key (throws if not available)
    [[nodiscard]] auto secretKey() const -> const seal::SecretKey&;

    /// Get relinearization keys (throws if not available)
    [[nodiscard]] auto relinKeys() const -> const seal::RelinKeys&;

    /// Get Galois keys (throws if not available)
    [[nodiscard]] auto galoisKeys() const -> const seal::GaloisKeys&;

    // ==================== Error Handling ====================

    /// Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

  private:
    struct Impl;
    std::unique_ptr< Impl > impl_;
  };

} // namespace sealcrypt
