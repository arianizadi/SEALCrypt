// Test: HomomorphicInt::noiseBudget()

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: HomomorphicInt::noiseBudget()" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  auto enc = sealcrypt::HomomorphicInt::encrypt(42, ctx, keys);

  int budget_initial = enc.noiseBudget(ctx, keys);
  if(budget_initial <= 0) {
    std::cerr << "FAIL: initial noise budget should be positive, got "
              << budget_initial << std::endl;
    return 1;
  }

  // Multiplication consumes noise budget
  auto enc_squared = enc * enc;
  int budget_after_mul = enc_squared.noiseBudget(ctx, keys);

  if(budget_after_mul >= budget_initial) {
    std::cerr << "FAIL: noise budget should decrease after multiplication"
              << std::endl;
    std::cerr << "  Before: " << budget_initial
              << ", After: " << budget_after_mul << std::endl;
    return 1;
  }

  std::cout << "PASS (initial=" << budget_initial
            << ", after mul=" << budget_after_mul << ")" << std::endl;
  return 0;
}
