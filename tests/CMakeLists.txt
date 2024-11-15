enable_testing()

# Add test executable
add_executable(sealcrypt_tests
    test_decryptor.cpp
    test_encryptor.cpp
    test_file_handler.cpp
)

# Link with the main library
target_link_libraries(sealcrypt_tests PRIVATE sealcrypt)

# Add test to CTest
add_test(NAME sealcrypt_tests COMMAND sealcrypt_tests)
