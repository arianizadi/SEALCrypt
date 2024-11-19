# Find GTest package
find_package(GTest REQUIRED)

# Create test executables
set(TEST_SOURCES
    test_encryptor.cpp
    test_decryptor.cpp
    test_file_handler.cpp
)

foreach(test_source ${TEST_SOURCES})
    # Get the filename without extension
    get_filename_component(test_name ${test_source} NAME_WE)
    # Create test executable
    add_executable(${test_name} ${test_source})
    # Link against GTest and your library
    target_link_libraries(${test_name}
        PRIVATE
        sealcrypt::sealcrypt
        GTest::GTest
        GTest::Main
    )
    # Add test to CTest
    add_test(NAME ${test_name} COMMAND ${test_name})
    # Set test properties (optional)
    set_tests_properties(${test_name}
        PROPERTIES
        TIMEOUT 30  # Timeout in seconds
        WILL_FAIL FALSE
    )
endforeach()
