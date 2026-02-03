#pragma once

#include "sealcrypt/context.hpp"
#include "sealcrypt/keys.hpp"

#include <memory>
#include <seal/seal.h>
#include <string>

namespace sealcrypt {

  /// HomomorphicInt represents an encrypted integer that supports
  /// arithmetic operations while remaining encrypted.
  ///
  /// Example usage:
  /// @code
  ///   CryptoContext ctx;
  ///   KeyPair keys(ctx);
  ///   keys.generate();
  ///
  ///   auto a = HomomorphicInt::encrypt(100, ctx, keys);
  ///   auto b = HomomorphicInt::encrypt(50, ctx, keys);
  ///   auto sum = a + b;
  ///   int64_t result = sum.decrypt(ctx, keys);  // 150
  /// @endcode
  class HomomorphicInt {
  public:
    // ==================== Constructors / Destructor ====================

    /// Create an empty HomomorphicInt
    HomomorphicInt();
    ~HomomorphicInt();

    // Copy only (no move)
    HomomorphicInt(const HomomorphicInt& other);
    auto operator=(const HomomorphicInt& other) -> HomomorphicInt&;

    // ==================== Encryption / Decryption ====================

    /// Encrypt an integer value
    /// @param value The integer to encrypt
    /// @param ctx The crypto context
    /// @param keys KeyPair with public key available
    /// @return Encrypted HomomorphicInt
    static auto encrypt(std::int64_t value,
                        const CryptoContext& ctx,
                        const KeyPair& keys) -> HomomorphicInt;

    /// Decrypt to get the original integer
    /// @param ctx The crypto context
    /// @param keys KeyPair with secret key available
    /// @return The decrypted integer value
    [[nodiscard]] auto decrypt(const CryptoContext& ctx,
                               const KeyPair& keys) const -> std::int64_t;

    // ==================== Arithmetic Operators (Ciphertext + Ciphertext)
    // ====================

    /// Homomorphic addition
    auto operator+(const HomomorphicInt& other) const -> HomomorphicInt;

    /// Homomorphic subtraction
    auto operator-(const HomomorphicInt& other) const -> HomomorphicInt;

    /// Homomorphic multiplication
    auto operator*(const HomomorphicInt& other) const -> HomomorphicInt;

    /// Homomorphic negation
    auto operator-() const -> HomomorphicInt;

    /// In-place addition
    auto operator+=(const HomomorphicInt& other) -> HomomorphicInt&;

    /// In-place subtraction
    auto operator-=(const HomomorphicInt& other) -> HomomorphicInt&;

    /// In-place multiplication
    auto operator*=(const HomomorphicInt& other) -> HomomorphicInt&;

    // ==================== Arithmetic with Plaintexts ====================
    // More efficient than encrypting the plaintext first

    /// Add a plaintext value
    auto addPlain(std::int64_t value, const CryptoContext& ctx) const
        -> HomomorphicInt;

    /// Subtract a plaintext value
    auto subPlain(std::int64_t value, const CryptoContext& ctx) const
        -> HomomorphicInt;

    /// Multiply by a plaintext value
    auto mulPlain(std::int64_t value, const CryptoContext& ctx) const
        -> HomomorphicInt;

    // ==================== Advanced Operations ====================

    /// Square the encrypted value (more efficient than a * a)
    auto square(const CryptoContext& ctx) const -> HomomorphicInt;

    /// Raise to a power (exponentiation)
    /// @param exponent The power to raise to (must be positive)
    /// @param ctx The crypto context
    /// @param keys KeyPair with relinearization keys
    auto power(std::uint64_t exponent,
               const CryptoContext& ctx,
               const KeyPair& keys) const -> HomomorphicInt;

    /// Relinearize after multiplication to reduce ciphertext size
    /// @param ctx The crypto context
    /// @param keys KeyPair with relinearization keys
    auto relinearize(const CryptoContext& ctx, const KeyPair& keys) const
        -> HomomorphicInt;

    /// Mod switch to next level (reduces noise budget consumption)
    /// @param ctx The crypto context
    auto modSwitchToNext(const CryptoContext& ctx) const -> HomomorphicInt;

    // ==================== Utility / Info ====================

    /// Check if this contains valid encrypted data
    [[nodiscard]] auto isValid() const -> bool;

    /// Get the noise budget remaining (bits)
    /// Lower noise budget = closer to decryption failure
    /// @param ctx The crypto context
    /// @param keys KeyPair with secret key
    /// @return Noise budget in bits, or -1 on error
    [[nodiscard]] auto noiseBudget(const CryptoContext& ctx,
                                   const KeyPair& keys) const -> int;

    /// Get ciphertext size (number of polynomials)
    /// Size increases after multiplication, relinearization reduces it
    [[nodiscard]] auto size() const -> std::size_t;

    /// Check if ciphertext is transparent (trivially decryptable - security
    /// risk)
    [[nodiscard]] auto isTransparent() const -> bool;

    /// Get last error message
    [[nodiscard]] auto getLastError() const -> std::string;

    // ==================== Serialization ====================

    /// Save encrypted value to file
    auto save(const std::string& path, const CryptoContext& ctx) const -> bool;

    /// Load encrypted value from file
    auto load(const std::string& path, const CryptoContext& ctx) -> bool;

    /// Serialize to byte vector
    [[nodiscard]] auto serialize(const CryptoContext& ctx) const
        -> std::vector< std::uint8_t >;

    /// Deserialize from byte vector
    auto deserialize(const std::vector< std::uint8_t >& data,
                     const CryptoContext& ctx) -> bool;

    // ==================== Advanced Access ====================

    /// Get the underlying ciphertext (for advanced users)
    [[nodiscard]] auto ciphertext() const -> const seal::Ciphertext&;

    /// Get mutable ciphertext (for advanced users)
    [[nodiscard]] auto ciphertextMut() -> seal::Ciphertext&;

    /// Set the context for operations
    void setContext(const CryptoContext* ctx);

  private:
    struct Impl;
    std::unique_ptr< Impl > impl_;

    // Private constructor for internal use
    explicit HomomorphicInt(seal::Ciphertext ct, const CryptoContext* ctx);
  };

} // namespace sealcrypt
