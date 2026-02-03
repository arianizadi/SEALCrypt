#pragma once

#include <memory>
#include <seal/seal.h>
#include <string>

namespace sealcrypt {

  /// Security level presets for easy configuration
  enum class SecurityLevel { Low, Medium, High };

  /// CryptoContext manages SEAL encryption parameters and context.
  /// This is the foundation that all other classes use.
  /// Create one context and share it across KeyPair, Encryptor, etc.
  class CryptoContext {
  public:
    /// Create context with security level preset
    /// @param level Security level (affects performance vs security tradeoff)
    explicit CryptoContext(SecurityLevel level = SecurityLevel::Medium);

    /// Create context with custom parameters
    /// @param poly_modulus_degree Polynomial modulus degree (4096, 8192, 16384)
    /// @param plain_modulus Plaintext modulus (must be prime for batching)
    CryptoContext(std::size_t poly_modulus_degree, std::uint64_t plain_modulus);

    ~CryptoContext();

    // Non-copyable, movable
    CryptoContext(const CryptoContext&) = delete;
    auto operator=(const CryptoContext&) -> CryptoContext& = delete;
    CryptoContext(CryptoContext&&) noexcept;
    auto operator=(CryptoContext&&) noexcept -> CryptoContext&;

    /// Check if context is valid and ready to use
    [[nodiscard]] auto isValid() const -> bool;

    /// Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

    /// Get the underlying SEAL context (for advanced users)
    [[nodiscard]] auto sealContext() const -> const seal::SEALContext&;

    /// Get the evaluator for homomorphic operations
    [[nodiscard]] auto evaluator() const -> seal::Evaluator&;

    /// Get encryption parameters info
    [[nodiscard]] auto polyModulusDegree() const -> std::size_t;
    [[nodiscard]] auto plainModulus() const -> std::uint64_t;

  private:
    struct Impl;
    std::unique_ptr< Impl > impl_;
  };

} // namespace sealcrypt
