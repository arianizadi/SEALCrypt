enable_testing()

# Function to create test executable
function(add_sealcrypt_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE sealcrypt)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    set_tests_properties(${TEST_NAME}
        PROPERTIES
        FAIL_REGULAR_EXPRESSION ".*failed.*"
        PASS_REGULAR_EXPRESSION ".*passed.*"
    )
endfunction()

# Add individual test executables
add_sealcrypt_test(test_decryptor)
add_sealcrypt_test(test_encryptor)
add_sealcrypt_test(test_file_handler)

# Optional: Add a target to run all tests
add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_decryptor test_encryptor test_file_handler
)
