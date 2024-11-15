#pragma once

#include <memory>
#include <seal/seal.h>
#include <string>
#include <vector>

namespace sealcrypt {

  class Verify {
  public:
    Verify();
    ~Verify() = default;

    // Verify encrypted data against original plaintext
    auto verify_encryption(const std::vector< uint64_t >& plain_data,
                           const seal::Ciphertext& encrypted_data,
                           const std::shared_ptr< seal::SEALContext >& context,
                           const seal::SecretKey& secret_key) -> bool;

    // Get the last error message
    [[nodiscard]] auto get_last_error() const -> std::string {
      return last_error_;
    }

  private:
    // Decrypt and compare values
    auto compare_decrypted_values(const std::vector< uint64_t >& original,
                                  const std::vector< uint64_t >& decrypted)
        -> bool;

    // Helper to decode plaintext into vector
    std::vector< uint64_t > decode_plaintext(const seal::Plaintext& plain,
                                             const seal::BatchEncoder& encoder);

    std::string last_error_;
  };

} // namespace sealcrypt