#pragma once

#include "sealcrypt/context.hpp"
#include "sealcrypt/keys.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sealcrypt {

  /// Encryptor handles file encryption using homomorphic encryption.
  /// Uses a shared CryptoContext for consistent parameters.
  class Encryptor {
  public:
    /// Create an Encryptor with a shared crypto context
    /// @param ctx The crypto context (must outlive this Encryptor)
    explicit Encryptor(const CryptoContext& ctx);

    ~Encryptor();

    // Non-copyable, movable
    Encryptor(const Encryptor&) = delete;
    auto operator=(const Encryptor&) -> Encryptor& = delete;
    Encryptor(Encryptor&&) noexcept;
    auto operator=(Encryptor&&) noexcept -> Encryptor&;

    /// Encrypt a file
    /// @param input_path Path to the plaintext file
    /// @param output_path Path for the encrypted output
    /// @param keys KeyPair with public key available
    /// @return true if successful
    auto encryptFile(const std::string& input_path,
                     const std::string& output_path,
                     const KeyPair& keys) -> bool;

    /// Encrypt raw bytes
    /// @param data The bytes to encrypt
    /// @param keys KeyPair with public key available
    /// @return Encrypted data as bytes, or empty on failure
    auto encryptBytes(const std::vector< std::uint8_t >& data,
                      const KeyPair& keys) -> std::vector< std::uint8_t >;

    /// Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

  private:
    struct Impl;
    std::unique_ptr< Impl > impl_;
  };

} // namespace sealcrypt
