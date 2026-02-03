#pragma once

#include "sealcrypt/context.hpp"
#include "sealcrypt/keys.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sealcrypt {

  /// Decryptor handles file decryption of homomorphically encrypted data.
  /// Uses a shared CryptoContext for consistent parameters.
  class Decryptor {
  public:
    /// Create a Decryptor with a shared crypto context
    /// @param ctx The crypto context (must outlive this Decryptor)
    explicit Decryptor(const CryptoContext& ctx);

    ~Decryptor();

    // Non-copyable, movable
    Decryptor(const Decryptor&) = delete;
    auto operator=(const Decryptor&) -> Decryptor& = delete;
    Decryptor(Decryptor&&) noexcept;
    auto operator=(Decryptor&&) noexcept -> Decryptor&;

    /// Decrypt a file
    /// @param input_path Path to the encrypted file
    /// @param output_path Path for the decrypted output
    /// @param keys KeyPair with secret key available
    /// @return true if successful
    auto decryptFile(const std::string& input_path,
                     const std::string& output_path,
                     const KeyPair& keys) -> bool;

    /// Decrypt raw bytes
    /// @param data The encrypted bytes
    /// @param keys KeyPair with secret key available
    /// @return Decrypted data as bytes, or empty on failure
    auto decryptBytes(const std::vector< std::uint8_t >& data,
                      const KeyPair& keys) -> std::vector< std::uint8_t >;

    /// Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

  private:
    struct Impl;
    std::unique_ptr< Impl > impl_;
  };

} // namespace sealcrypt
