#include "sealcrypt/context.hpp"

namespace sealcrypt {

  struct CryptoContext::Impl {
    std::unique_ptr< seal::SEALContext > context;
    std::unique_ptr< seal::Evaluator > evaluator;
    std::size_t poly_modulus_degree {0};
    std::uint64_t plain_modulus {0};
    std::string last_error;
    bool valid {false};

    auto initialize(std::size_t poly_deg, std::uint64_t plain_mod) -> bool {
      try {
        poly_modulus_degree = poly_deg;
        plain_modulus = plain_mod;

        seal::EncryptionParameters params(seal::scheme_type::bfv);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(
            seal::CoeffModulus::BFVDefault(poly_modulus_degree));
        params.set_plain_modulus(plain_modulus);

        context = std::make_unique< seal::SEALContext >(params);

        if(!context->parameters_set()) {
          last_error = "Failed to set encryption parameters";
          return false;
        }

        evaluator = std::make_unique< seal::Evaluator >(*context);
        valid = true;
        return true;

      } catch(const std::exception& e) {
        last_error = "Context initialization failed: " + std::string(e.what());
        return false;
      }
    }
  };

  CryptoContext::CryptoContext(SecurityLevel level) :
      impl_(std::make_unique< Impl >()) {
    // Security level presets
    // Higher poly_modulus_degree = more security but slower
    // plain_modulus must be prime for optimal performance
    switch(level) {
      case SecurityLevel::Low:
        impl_->initialize(4096, 65537); // Fast, 128-bit security
        break;
      case SecurityLevel::Medium:
        impl_->initialize(8192, 65537); // Balanced, 192-bit security
        break;
      case SecurityLevel::High:
        impl_->initialize(16384, 65537); // Slower, 256-bit security
        break;
    }
  }

  CryptoContext::CryptoContext(std::size_t poly_modulus_degree,
                               std::uint64_t plain_modulus) :
      impl_(std::make_unique< Impl >()) {
    impl_->initialize(poly_modulus_degree, plain_modulus);
  }

  CryptoContext::~CryptoContext() = default;

  CryptoContext::CryptoContext(CryptoContext&&) noexcept = default;
  auto CryptoContext::operator=(CryptoContext&&) noexcept
      -> CryptoContext& = default;

  auto CryptoContext::isValid() const -> bool {
    return impl_ && impl_->valid;
  }

  auto CryptoContext::getLastError() const -> std::string {
    return impl_ ? impl_->last_error : "Context not initialized";
  }

  auto CryptoContext::sealContext() const -> const seal::SEALContext& {
    return *impl_->context;
  }

  auto CryptoContext::evaluator() const -> seal::Evaluator& {
    return *impl_->evaluator;
  }

  auto CryptoContext::polyModulusDegree() const -> std::size_t {
    return impl_ ? impl_->poly_modulus_degree : 0;
  }

  auto CryptoContext::plainModulus() const -> std::uint64_t {
    return impl_ ? impl_->plain_modulus : 0;
  }

} // namespace sealcrypt
