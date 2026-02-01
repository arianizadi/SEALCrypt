# SEALCrypt

SEALCrypt is a C++ library that provides homomorphic encryption capabilities using Microsoft SEAL. It offers a simplified interface for common encryption operations while leveraging the power of SEAL's homomorphic encryption features.

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

## Usage

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

### Example Usage

```bash
# 1. Create a test file
echo 'HELLOOOOOOO!' > secret.txt

# 2. Generate keys
./sealcrypt generate-keys --public-key public.key --private-key private.key

# 3. Encrypt the file
./sealcrypt encrypt --input secret.txt --output secret.encrypted --public-key public.key

# 4. Decrypt the file
./sealcrypt decrypt --input secret.encrypted --output secret_decrypted.txt --private-key private.key

# 5. Verify
cat secret_decrypted.txt
```

## Testing

```bash
# Build and run all tests
cd build
make
make run_all_tests

# Run specific test
./tests/test_encryptor
./tests/test_decryptor
./tests/test_file_handler
```

## Example CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(TestProject)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the SEALCrypt library
find_package(SEALCrypt REQUIRED)

# Add the executable
add_executable(main main.cpp)

# Link the SEALCrypt library
target_link_libraries(main PRIVATE sealcrypt::sealcrypt)
```

### Key Components

- **Encryptor**: Handles encryption operations using SEAL's homomorphic encryption
- **Decryptor**: Manages decryption of homomorphically encrypted data
- **FileHandler**: Provides thread-safe file operations for encrypted data
