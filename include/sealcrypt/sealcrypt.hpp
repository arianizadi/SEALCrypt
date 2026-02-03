#pragma once

/// @file sealcrypt.hpp
/// @brief Main include file for SEALCrypt library
///
/// Include this single header to get access to all SEALCrypt functionality.
///
/// @example Basic Usage
/// @code
/// #include <sealcrypt/sealcrypt.hpp>
/// #include <iostream>
///
/// int main() {
///     // Create context with medium security
///     sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
///
///     // Generate keys
///     sealcrypt::KeyPair keys(ctx);
///     keys.generate();
///     keys.save("public.key", "private.key");
///
///     // Homomorphic operations
///     auto a = sealcrypt::HomomorphicInt::encrypt(100, ctx, keys);
///     auto b = sealcrypt::HomomorphicInt::encrypt(50, ctx, keys);
///     auto sum = a + b;
///     std::cout << "100 + 50 = " << sum.decrypt(ctx, keys) << std::endl;
///
///     // File encryption
///     sealcrypt::Encryptor enc(ctx);
///     enc.encryptFile("secret.txt", "secret.enc", keys);
///
///     sealcrypt::Decryptor dec(ctx);
///     dec.decryptFile("secret.enc", "decrypted.txt", keys);
///
///     return 0;
/// }
/// @endcode

#include "sealcrypt/context.hpp"
#include "sealcrypt/decrypt.hpp"
#include "sealcrypt/encrypt.hpp"
#include "sealcrypt/file_handler.hpp"
#include "sealcrypt/homomorphic.hpp"
#include "sealcrypt/keys.hpp"
