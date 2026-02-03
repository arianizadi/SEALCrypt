# SEALCrypt

SEALCrypt is a C++ library that provides a simple, user-friendly interface for homomorphic encryption using Microsoft SEAL. It makes it easy to perform computations on encrypted data without ever decrypting it.

## Features

- **Simple API** - Clean, intuitive interface that hides SEAL complexity
- **Homomorphic Operations** - Add, subtract, and multiply encrypted values using natural operators (`+`, `-`, `*`)
- **File Encryption** - Encrypt and decrypt files with homomorphic encryption
- **Security Presets** - Choose from Low, Medium, or High security levels

## Prerequisites

- CMake (>= 3.12)
- C++17 compatible compiler
- Microsoft SEAL (>= 4.1)
- Git (for installation)

## Installation

### Building from Source

```bash
git clone https://github.com/arianizadi/SEALCrypt.git
cd SEALCrypt
mkdir build && cd build
cmake ..
make
sudo make install
```

### Uninstalling

```bash
# From the build directory
sudo make uninstall
```

## Quick Start

### Homomorphic Addition Example

```cpp
#include <sealcrypt/sealcrypt.hpp>
#include <iostream>

int main() {
    // Create context with medium security
    sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);

    // Generate keys
    sealcrypt::KeyPair keys(ctx);
    keys.generate();

    // Encrypt two numbers
    auto a = sealcrypt::HomomorphicInt::encrypt(100, ctx, keys);
    auto b = sealcrypt::HomomorphicInt::encrypt(50, ctx, keys);

    // Add them while encrypted!
    auto sum = a + b;

    // Decrypt to see the result
    std::cout << "100 + 50 = " << sum.decrypt(ctx, keys) << std::endl;  // 150

    return 0;
}
```

### File Encryption Example

```cpp
#include <sealcrypt/sealcrypt.hpp>

int main() {
    sealcrypt::CryptoContext ctx;
    sealcrypt::KeyPair keys(ctx);
    keys.generate();
    keys.save("public.key", "private.key");

    // Encrypt a file
    sealcrypt::Encryptor encryptor(ctx);
    encryptor.encryptFile("secret.txt", "secret.enc", keys);

    // Decrypt a file
    sealcrypt::Decryptor decryptor(ctx);
    decryptor.decryptFile("secret.enc", "decrypted.txt", keys);

    return 0;
}
```

## CLI Usage

```bash
# Generate keys
./sealcrypt generate-keys --public public.key --private private.key

# Encrypt a file
./sealcrypt encrypt --input secret.txt --output secret.enc --public-key public.key

# Decrypt a file
./sealcrypt decrypt --input secret.enc --output decrypted.txt --private-key private.key
```

## API Reference

### CryptoContext

The foundation for all encryption operations.

```cpp
// Create with security preset
sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);

// Or with custom parameters
sealcrypt::CryptoContext ctx(8192, 65537);
```

### KeyPair

Manages public and secret keys.

```cpp
sealcrypt::KeyPair keys(ctx);
keys.generate();                           // Generate new keys
keys.save("pub.key", "priv.key");         // Save to files
keys.load("pub.key", "priv.key");         // Load from files
keys.loadPublicKey("pub.key");            // Load only public key
keys.loadSecretKey("priv.key");           // Load only secret key
```

### HomomorphicInt

Encrypted integers with arithmetic operators.

```cpp
auto a = sealcrypt::HomomorphicInt::encrypt(100, ctx, keys);
auto b = sealcrypt::HomomorphicInt::encrypt(50, ctx, keys);

auto sum = a + b;           // Homomorphic addition
auto diff = a - b;          // Homomorphic subtraction
auto prod = a * b;          // Homomorphic multiplication
auto neg = -a;              // Negation

auto result = sum.addPlain(10, ctx);  // Add plaintext (more efficient)
auto squared = a.square(ctx);          // Square

int64_t value = sum.decrypt(ctx, keys);  // Decrypt to get result
```

### Encryptor / Decryptor

File encryption and decryption.

```cpp
sealcrypt::Encryptor encryptor(ctx);
encryptor.encryptFile("input.txt", "output.enc", keys);

sealcrypt::Decryptor decryptor(ctx);
decryptor.decryptFile("output.enc", "decrypted.txt", keys);
```

## CMake Integration

```cmake
cmake_minimum_required(VERSION 3.12)
project(MyProject)

set(CMAKE_CXX_STANDARD 17)

find_package(sealcrypt REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE sealcrypt::sealcrypt)
```

## Testing

```bash
cd build
make
ctest --output-on-failure
```

## Security Levels

| Level  | Poly Modulus | Security | Speed    |
| ------ | ------------ | -------- | -------- |
| Low    | 4096         | 128-bit  | Fastest  |
| Medium | 8192         | 192-bit  | Balanced |
| High   | 16384        | 256-bit  | Slowest  |

## Key Components

- **CryptoContext**: Shared encryption parameters and SEAL context
- **KeyPair**: Public/secret key management with save/load support
- **HomomorphicInt**: Encrypted integers with operator overloading
- **Encryptor**: File encryption using homomorphic encryption
- **Decryptor**: File decryption with correct handling of all byte values
- **FileHandler**: File I/O utilities
