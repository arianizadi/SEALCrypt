// Test: Polynomial evaluation ax^2 + bx + c

#include "sealcrypt/sealcrypt.hpp"

#include <iostream>

auto main() -> int {
  std::cout << "Test: Polynomial evaluation ax^2 + bx + c" << std::endl;

  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Low);
  sealcrypt::KeyPair keys(ctx);

  if(!keys.generate()) {
    std::cerr << "FAIL: keys.generate() failed" << std::endl;
    return 1;
  }

  // Evaluate 2x^2 + 3x + 5 at x = 4
  // Expected: 2*16 + 3*4 + 5 = 32 + 12 + 5 = 49
  std::int64_t x = 4;
  std::int64_t a = 2;
  std::int64_t b = 3;
  std::int64_t c = 5;
  std::int64_t expected = a * x * x + b * x + c;

  auto enc_x = sealcrypt::HomomorphicInt::encrypt(x, ctx, keys);

  // Compute x^2
  auto enc_x2 = enc_x.square(ctx);

  // Compute ax^2
  auto enc_ax2 = enc_x2.mulPlain(a, ctx);

  // Compute bx
  auto enc_bx = enc_x.mulPlain(b, ctx);

  // Compute ax^2 + bx + c
  auto enc_result = enc_ax2 + enc_bx;
  enc_result = enc_result.addPlain(c, ctx);

  if(!enc_result.isValid()) {
    std::cerr << "FAIL: polynomial result is invalid" << std::endl;
    return 1;
  }

  std::int64_t result = enc_result.decrypt(ctx, keys);
  if(result != expected) {
    std::cerr << "FAIL: " << a << "*" << x << "^2 + " << b << "*" << x << " + "
              << c << " = " << result << ", expected " << expected << std::endl;
    return 1;
  }

  std::cout << "PASS: " << a << "x^2 + " << b << "x + " << c << " at x=" << x
            << " = " << result << std::endl;
  return 0;
}
