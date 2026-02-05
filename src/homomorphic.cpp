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
    if(!this->isValid() || !other.isValid()) {
      return {};
    }
    seal::Ciphertext result;
    this->impl_->ctx->evaluator().add(
        this->ciphertext(), other.ciphertext(), result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::operator-(const HomomorphicInt& other) const
      -> HomomorphicInt {
    if(!this->isValid() || !other.isValid()) {
      return {};
    }
    seal::Ciphertext result;
    this->impl_->ctx->evaluator().sub(
        this->ciphertext(), other.ciphertext(), result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::operator*(const HomomorphicInt& other) const
      -> HomomorphicInt {
    if(!this->isValid() || !other.isValid()) {
      return {};
    }
    seal::Ciphertext result;
    this->impl_->ctx->evaluator().multiply(
        this->ciphertext(), other.ciphertext(), result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::operator-() const -> HomomorphicInt {
    if(!this->isValid()) {
      return {};
    }
    seal::Ciphertext result;
    this->impl_->ctx->evaluator().negate(this->ciphertext(), result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::operator+=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    if(!this->isValid() || !other.isValid()) {
      return *this;
    }
    this->impl_->ctx->evaluator().add_inplace(this->impl_->ciphertext,
                                              other.ciphertext());
    return *this;
  }

  auto HomomorphicInt::operator-=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    if(!this->isValid() || !other.isValid()) {
      return *this;
    }
    this->impl_->ctx->evaluator().sub_inplace(this->impl_->ciphertext,
                                              other.ciphertext());
    return *this;
  }

  auto HomomorphicInt::operator*=(const HomomorphicInt& other)
      -> HomomorphicInt& {
    if(!this->isValid() || !other.isValid()) {
      return *this;
    }
    this->impl_->ctx->evaluator().multiply_inplace(this->impl_->ciphertext,
                                                   other.ciphertext());
    return *this;
  }

  // ==================== Plaintext Operations ====================

  auto HomomorphicInt::addPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    if(!ctx.isValid() || !this->isValid()) {
      return {};
    }
    seal::Plaintext plaintext(toHexString(value));
    seal::Ciphertext result;
    ctx.evaluator().add_plain(ciphertext(), plaintext, result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::subPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    if(!ctx.isValid() || !this->isValid()) {
      return {};
    }
    seal::Plaintext plaintext(toHexString(value));
    seal::Ciphertext result;
    ctx.evaluator().sub_plain(ciphertext(), plaintext, result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::mulPlain(std::int64_t value,
                                const CryptoContext& ctx) const
      -> HomomorphicInt {
    if(!ctx.isValid() || !this->isValid()) {
      return {};
    }
    seal::Plaintext plaintext(toHexString(value));
    seal::Ciphertext result;
    ctx.evaluator().multiply_plain(ciphertext(), plaintext, result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  // ==================== Advanced Operations ====================

  auto HomomorphicInt::square(const CryptoContext& ctx) const
      -> HomomorphicInt {
    if(!ctx.isValid() || !this->isValid()) {
      return {};
    }
    seal::Ciphertext result;
    this->impl_->ctx->evaluator().square(ciphertext(), result);
    return HomomorphicInt(result, this->impl_->ctx);
  }

  auto HomomorphicInt::power(std::uint64_t exponent,
                             const CryptoContext& ctx,
                             const KeyPair& keys) const -> HomomorphicInt {
    if(!ctx.isValid() || !this->isValid()) {
      return {};
    }
    if(!keys.hasRelinKeys()) {
      return {};
    }
    seal::Ciphertext result;
    ctx.evaluator().exponentiate(
        this->ciphertext(), exponent, keys.relinKeys(), result);
    return HomomorphicInt(result, &ctx);
  }

  auto HomomorphicInt::relinearize(const CryptoContext& ctx,
                                   const KeyPair& keys) const
      -> HomomorphicInt {
    if(!this->isValid() || !ctx.isValid()) {
      return {};
    }
    if(!keys.hasRelinKeys()) {
      return {};
    }
    seal::Ciphertext result;
    ctx.evaluator().relinearize(ciphertext(), keys.relinKeys(), result);
    return HomomorphicInt(result, &ctx);
  }

  auto HomomorphicInt::modSwitchToNext(const CryptoContext& ctx) const
      -> HomomorphicInt {
    if(!this->isValid() || !ctx.isValid()) {
      return {};
    }
    seal::Ciphertext result;
    ctx.evaluator().mod_switch_to_next(this->ciphertext(), result);
    return HomomorphicInt(result, &ctx);
  }

  // ==================== Utility / Info ====================

  auto HomomorphicInt::isValid() const -> bool {
    return impl_->valid;
  }

  auto HomomorphicInt::noiseBudget(const CryptoContext& ctx,
                                   const KeyPair& keys) const -> int {
    if(!this->isValid() || !ctx.isValid() || !keys.hasSecretKey()) {
      return {};
    }
    seal::Decryptor decryptor(ctx.sealContext(), keys.secretKey());
    return decryptor.invariant_noise_budget(ciphertext());
  }

  auto HomomorphicInt::size() const -> std::size_t {
    if(!this->isValid()) {
      return 0;
    }
    return impl_->ciphertext.size();
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
    (void) ctx; // keep ctx arg so api is symmetric for file loads / saves, less
                // confusing
    if(!this->isValid()) {
      return false;
    }
    auto fstream = FileHandler::openForWriting(path, this->impl_->last_error);
    if(!fstream) {
      return false;
    }
    this->impl_->ciphertext.save(*fstream);
    return true;
  }

  auto HomomorphicInt::load(const std::string& path, const CryptoContext& ctx)
      -> bool {
    if(!ctx.isValid()) {
      return false;
    }
    auto fstream = FileHandler::openForReading(path, this->impl_->last_error);
    if(!fstream) {
      return false;
    }
    impl_->ciphertext.load(ctx.sealContext(), *fstream);
    impl_->ctx = &ctx;
    impl_->valid = true;
    return true;
  }

  auto HomomorphicInt::serialize(const CryptoContext& ctx) const
      -> std::vector< std::uint8_t > {
    (void)
        ctx; // keep ctx for deserliaze, i want the args to match for api sake
    if(!this->isValid()) {
      return {};
    }
    std::ostringstream stream(std::ios::binary);
    impl_->ciphertext.save(stream);
    auto str = stream.str();
    return {str.begin(), str.end()};
  }

  auto HomomorphicInt::deserialize(const std::vector< std::uint8_t >& data,
                                   const CryptoContext& ctx) -> bool {
    if(!ctx.isValid() || data.empty()) {
      return false;
    }
    std::string str(data.begin(), data.end());
    std::istringstream stream(str, std::ios::binary);
    impl_->ciphertext.load(ctx.sealContext(), stream);
    impl_->ctx = &ctx;
    impl_->valid = true;
    return true;
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
