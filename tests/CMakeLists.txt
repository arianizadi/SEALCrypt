include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

find_package(Threads REQUIRED)

set(KEYPAIR_TESTS
    test_keypair_generate.cpp
    test_keypair_generate_relin.cpp
    test_keypair_generate_galois.cpp
    test_keypair_generate_all.cpp
    test_keypair_save_load.cpp
    test_keypair_save_load_relin.cpp
)

set(HOMO_TESTS
    test_homo_encrypt_decrypt.cpp
    test_homo_isvalid.cpp
    test_homo_add.cpp
    test_homo_sub.cpp
    test_homo_mul.cpp
    test_homo_negate.cpp
    test_homo_add_inplace.cpp
    test_homo_sub_inplace.cpp
    test_homo_mul_inplace.cpp
    test_homo_add_plain.cpp
    test_homo_sub_plain.cpp
    test_homo_mul_plain.cpp
    test_homo_square.cpp
    test_homo_power.cpp
    test_homo_relinearize.cpp
    test_homo_mod_switch.cpp
    test_homo_noise_budget.cpp
    test_homo_size.cpp
    test_homo_is_transparent.cpp
    test_homo_save_load.cpp
    test_homo_serialize.cpp
    test_homo_chained_ops.cpp
    test_homo_polynomial.cpp
)

set(ALL_TESTS
    ${KEYPAIR_TESTS}
    ${HOMO_TESTS}
)

foreach(test_source ${ALL_TESTS})
    get_filename_component(test_name ${test_source} NAME_WE)
    add_executable(${test_name} ${test_source})
    target_include_directories(${test_name}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_include_directories(${test_name}
        BEFORE PRIVATE
        ${CMAKE_BINARY_DIR}/_deps/googletest-src/googletest/include
    )
    target_link_libraries(${test_name}
        PRIVATE
        gtest_main
        gtest
        sealcrypt::sealcrypt
        Threads::Threads
    )
    target_compile_features(${test_name} PRIVATE cxx_std_17)
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name}
        PROPERTIES
        TIMEOUT 60
        WILL_FAIL FALSE
    )
endforeach()

add_custom_target(test_keypair
    COMMAND ${CMAKE_CTEST_COMMAND} -R "keypair" --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running KeyPair tests"
)

add_custom_target(test_homo
    COMMAND ${CMAKE_CTEST_COMMAND} -R "homo" --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running HomomorphicInt tests"
)

add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running all tests"
)
