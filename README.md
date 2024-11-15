# SEALCrypt 🔐

SEALCrypt is a C++ library that provides homomorphic encryption capabilities using Microsoft SEAL. It offers a simplified interface for common encryption operations while leveraging the power of SEAL's homomorphic encryption features.

## 🌟 Features

- File encryption/decryption using homomorphic encryption
- Streamlined SEAL integration
- Thread-safe file handling
- Comprehensive test suite
- CMake-based build system
- Can be used as both a standalone executable and a library

## 📋 Prerequisites

- CMake (>= 3.12)
- C++17 compatible compiler
- Microsoft SEAL (>= 4.1)
- Git (for installation)

## 🚀 Installation

### Building from Source

```bash
git clone https://github.com/yourusername/SEALCrypt.git
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

## 💻 Usage

### As a Library

1. CMake Integration

```cmake
find_package(sealcrypt REQUIRED)
target_link_libraries(your_target PRIVATE sealcrypt::sealcrypt)
```

2. Basic Example

```cpp
#include <sealcrypt/encrypt.hpp>
#include <sealcrypt/decrypt.hpp>
#include <sealcrypt/file_handler.hpp>

int main() {
    // Your encryption/decryption code here
    return 0;
}
```

### As an Executable

```bash
# Encrypt a file
sealcrypt encrypt input.txt output.encrypted

# Decrypt a file
sealcrypt decrypt output.encrypted decrypted.txt
```

## 🧪 Testing

SEALCrypt comes with a comprehensive test suite. Each component has its own test file that can be run independently.

```bash
# Build and run all tests
cd build
make
ctest --output-on-failure

# Run specific test
./tests/test_encryptor
./tests/test_decryptor
./tests/test_file_handler
```

### Key Components

- **Encryptor**: Handles encryption operations using SEAL's homomorphic encryption
- **Decryptor**: Manages decryption of homomorphically encrypted data
- **FileHandler**: Provides thread-safe file operations for encrypted data
