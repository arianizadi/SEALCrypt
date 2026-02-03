#include "sealcrypt/homomorphic.hpp"

#include "sealcrypt/file_handler.hpp"

#include <algorithm>
#include <exception>
#include <seal/ciphertext.h>
#include <seal/decryptor.h>
#include <seal/encryptor.h>
#include <seal/plaintext.h>
#include <sstream>
#include <stdexcept>

namespace sealcrypt {

  // ==================== Helper Functions ====================

  namespace {

    auto toHexString(std::int64_t value) -> std::string {
      auto two_complement = static_cast< std::uint64_t >(value);
      std::ostringstream oss;
      oss << std::hex << two_complement;
      return oss.str();
    }

    auto fromHexString(const std::string& hex) -> std::int64_t {
      std::uint64_t value = 0;
      try {
        value = std::stoull(hex, nullptr, 16);
      } catch(const std::exception&) {
        return 0;
      }
      return static_cast< std::int64_t >(value);
    }

  } // namespace

  // ==================== Implementation Structure ====================

  struct HomomorphicInt::Impl {
    seal::Ciphertext ciphertext;
    const CryptoContext* ctx {nullptr};
    mutable std::string last_error;
    bool valid {false};
  };

  // ==================== Constructors / Destructor ====================

  HomomorphicInt::HomomorphicInt() : impl_(std::make_unique< Impl >()) {
  }

  HomomorphicInt::~HomomorphicInt() = default;

  HomomorphicInt::HomomorphicInt(const HomomorphicInt& other) :
      impl_(std::make_unique< Impl >()) {
    impl_->ciphertext = other.impl_->ciphertext;
    impl_->ctx = other.impl_->ctx;
    impl_->last_error = other.impl_->last_error;
    impl_->valid = other.impl_->valid;
  }

  auto HomomorphicInt::operator=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    if(this != &other) {
      impl_->ciphertext = other.impl_->ciphertext;
      impl_->ctx = other.impl_->ctx;
      impl_->last_error = other.impl_->last_error;
      impl_->valid = other.impl_->valid;
    }
    return *this;
  }

  HomomorphicInt::HomomorphicInt(seal::Ciphertext ct,
                                 const CryptoContext* ctx) :
      impl_(std::make_unique< Impl >()) {
    impl_->ciphertext = ct;
    impl_->ctx = ctx;
    impl_->valid = true;
  }

  // ==================== Encryption / Decryption ====================

  auto HomomorphicInt::encrypt(std::int64_t value,
                               const CryptoContext& ctx,
                               const KeyPair& keys) -> HomomorphicInt {
    if(!ctx.isValid() || !keys.hasPublicKey()) {
      return {};
    }

    try {
      seal::Encryptor encryptor(ctx.sealContext(), keys.publicKey());
      seal::Plaintext plaintext;
      plaintext.resize(1);
      auto unsigned_val = static_cast< std::uint64_t >(value);
      plaintext[0] = unsigned_val;
      seal::Ciphertext ciphertext;
      encryptor.encrypt(plaintext, ciphertext);
      return HomomorphicInt(std::move(ciphertext), &ctx);
    } catch(const std::exception& e) {
      HomomorphicInt result;
      result.impl_->last_error = "Encryption failed: " + std::string(e.what());
      return result;
    }
  }

  auto HomomorphicInt::decrypt(const CryptoContext& ctx,
                               const KeyPair& keys) const -> std::int64_t {
    if(!impl_->valid || !keys.hasSecretKey()) {
      return {};
    }
    try {
      seal::Decryptor decryptor(ctx.sealContext(), keys.secretKey());
      seal::Plaintext plaintext;
      decryptor.decrypt(impl_->ciphertext, plaintext);
      if(plaintext.coeff_count() == 0) {
        throw std::runtime_error("Decrypted plaintext is empty");
      }
      std::uint64_t unsigned_val = plaintext[0];
      return static_cast< std::int64_t >(unsigned_val);
    } catch(const std::exception& e) {
      throw std::runtime_error("Decryption failed: " + std::string(e.what()));
    }
  }

  // ==================== Arithmetic Operators ====================

  auto HomomorphicInt::operator+(const HomomorphicInt& other) const
      -> HomomorphicInt {
    // TODO: Implement homomorphic addition
    // 1. Check both operands are valid and context is set
    // 2. Use ctx->evaluator().add(this->ciphertext, other->ciphertext, result)
    // 3. Return new HomomorphicInt with result
    (void) other;
    return HomomorphicInt();
  }

  auto HomomorphicInt::operator-(const HomomorphicInt& other) const
      -> HomomorphicInt {
    // TODO: Implement homomorphic subtraction
    // Use ctx->evaluator().sub()
    (void) other;
    return HomomorphicInt();
  }

  auto HomomorphicInt::operator*(const HomomorphicInt& other) const
      -> HomomorphicInt {
    // TODO: Implement homomorphic multiplication
    // Use ctx->evaluator().multiply()
    // Note: Ciphertext size increases after multiplication
    (void) other;
    return HomomorphicInt();
  }

  auto HomomorphicInt::operator-() const -> HomomorphicInt {
    // TODO: Implement homomorphic negation
    // Use ctx->evaluator().negate()
    return HomomorphicInt();
  }

  auto HomomorphicInt::operator+=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    // TODO: Implement in-place addition
    // Hint: Can use *this = *this + other, or use add_inplace
    (void) other;
    return *this;
  }

  auto HomomorphicInt::operator-=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    // TODO: Implement in-place subtraction
    (void) other;
    return *this;
  }

  auto HomomorphicInt::operator*=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    // TODO: Implement in-place multiplication
    (void) other;
    return *this;
  }

  // ==================== Plaintext Operations ====================

  auto HomomorphicInt::addPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    // TODO: Add plaintext to ciphertext
    // 1. Create seal::Plaintext from toHexString(value)
    // 2. Use ctx.evaluator().add_plain(ciphertext, plaintext, result)
    // More efficient than encrypting value first
    (void) value;
    (void) ctx;
    return HomomorphicInt();
  }

  auto HomomorphicInt::subPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    // TODO: Subtract plaintext from ciphertext
    // Use ctx.evaluator().sub_plain()
    (void) value;
    (void) ctx;
    return HomomorphicInt();
  }

  auto HomomorphicInt::mulPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    // TODO: Multiply ciphertext by plaintext
    // Use ctx.evaluator().multiply_plain()
    (void) value;
    (void) ctx;
    return HomomorphicInt();
  }

  // ==================== Advanced Operations ====================

  auto HomomorphicInt::square(const CryptoContext& ctx) const
      -> HomomorphicInt {
    // TODO: Square the ciphertext
    // Use ctx.evaluator().square()
    // More efficient than multiply(this, this)
    (void) ctx;
    return HomomorphicInt();
  }

  auto HomomorphicInt::power(std::uint64_t exponent,
                             const CryptoContext& ctx,
                             const KeyPair& keys) const -> HomomorphicInt {
    // TODO: Raise ciphertext to a power
    // 1. Check keys.hasRelinKeys()
    // 2. Use ctx.evaluator().exponentiate(ciphertext, exponent,
    // keys.relinKeys(), result) Requires relinearization keys to manage
    // ciphertext size
    (void) exponent;
    (void) ctx;
    (void) keys;
    return HomomorphicInt();
  }

  auto HomomorphicInt::relinearize(const CryptoContext& ctx,
                                   const KeyPair& keys) const
      -> HomomorphicInt {
    // TODO: Relinearize ciphertext to reduce size
    // 1. Check keys.hasRelinKeys()
    // 2. Use ctx.evaluator().relinearize(ciphertext, keys.relinKeys(), result)
    // Should be called after multiplication to reduce size from 3 to 2
    (void) ctx;
    (void) keys;
    return HomomorphicInt();
  }

  auto HomomorphicInt::modSwitchToNext(const CryptoContext& ctx) const
      -> HomomorphicInt {
    // TODO: Switch to next modulus level
    // Use ctx.evaluator().mod_switch_to_next(ciphertext, result)
    // Reduces noise budget consumption but also reduces precision
    (void) ctx;
    return HomomorphicInt();
  }

  // ==================== Utility / Info ====================

  auto HomomorphicInt::isValid() const -> bool {
    return impl_->valid;
  }

  auto HomomorphicInt::noiseBudget(const CryptoContext& ctx,
                                   const KeyPair& keys) const -> int {
    // TODO: Get remaining noise budget
    // 1. Create seal::Decryptor
    // 2. Return decryptor.invariant_noise_budget(ciphertext)
    // When noise budget reaches 0, decryption will fail
    (void) ctx;
    (void) keys;
    return -1;
  }

  auto HomomorphicInt::size() const -> std::size_t {
    // TODO: Return ciphertext size (number of polynomials)
    // Fresh ciphertext has size 2
    // After multiplication (before relinearization) has size 3
    // Return impl_->ciphertext.size()
    return 0;
  }

  // transparent encryption means it can be decrypted without secret key
  auto HomomorphicInt::isTransparent() const -> bool {
    return impl_->ciphertext.is_transparent();
  }

  auto HomomorphicInt::getLastError() const -> std::string {
    return impl_->last_error;
  }

  // ==================== Serialization ====================

  auto HomomorphicInt::save(const std::string& path,
                            const CryptoContext& ctx) const -> bool {
    // TODO: Save ciphertext to file
    // 1. Check impl_->valid
    // 2. Use FileHandler::openForWriting()
    // 3. Call impl_->ciphertext.save(*file)
    (void) path;
    (void) ctx;
    return false;
  }

  auto HomomorphicInt::load(const std::string& path, const CryptoContext& ctx)
      -> bool {
    // TODO: Load ciphertext from file
    // 1. Use FileHandler::openForReading()
    // 2. Call impl_->ciphertext.load(ctx.sealContext(), *file)
    // 3. Set impl_->ctx and impl_->valid
    (void) path;
    (void) ctx;
    return false;
  }

  auto HomomorphicInt::serialize(const CryptoContext& ctx) const
      -> std::vector< std::uint8_t > {
    // TODO: Serialize ciphertext to bytes
    // 1. Create std::ostringstream
    // 2. Call impl_->ciphertext.save(stream)
    // 3. Convert stream to vector<uint8_t>
    (void) ctx;
    return {};
  }

  auto HomomorphicInt::deserialize(const std::vector< std::uint8_t >& data,
                                   const CryptoContext& ctx) -> bool {
    // TODO: Deserialize ciphertext from bytes
    // 1. Create std::istringstream from data
    // 2. Call impl_->ciphertext.load(ctx.sealContext(), stream)
    // 3. Set impl_->ctx and impl_->valid
    (void) data;
    (void) ctx;
    return false;
  }

  // ==================== Advanced Access ====================

  auto HomomorphicInt::ciphertext() const -> const seal::Ciphertext& {
    if(!impl_->valid) {
      throw std::runtime_error("No valid ciphertext");
    }
    return impl_->ciphertext;
  }

  auto HomomorphicInt::ciphertextMut() -> seal::Ciphertext& {
    if(!impl_->valid) {
      throw std::runtime_error("No valid ciphertext");
    }
    return impl_->ciphertext;
  }

  void HomomorphicInt::setContext(const CryptoContext* ctx) {
    impl_->ctx = ctx;
  }

} // namespace sealcrypt
