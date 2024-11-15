cmake_minimum_required(VERSION 3.12)
project(SEALCRYPT VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard (SEAL requires C++17 or higher)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Microsoft SEAL package
find_package(SEAL 4.1 REQUIRED)

# Function to check SEAL configuration
if(NOT SEAL_FOUND)
    message(FATAL_ERROR "Microsoft SEAL not found. Please install SEAL or provide its location.")
endif()

# Check if SEAL was built with the required features
if(SEAL_USE_CXX17)
    message(STATUS "SEAL C++17 support: YES")
else()
    message(WARNING "SEAL was not built with C++17 support. This might cause issues.")
endif()

# Optional: Check for specific SEAL components you need
if(SEAL_USE_ZLIB)
    message(STATUS "SEAL ZLIB support: YES")
else()
    message(STATUS "SEAL ZLIB support: NO")
endif()


# Define source files for the library
set(SEALCRYPT_LIB_SOURCES
    src/encrypt.cpp
    src/decrypt.cpp
    src/file_handler.cpp
)

# Define headers
set(SEALCRYPT_HEADERS
    include/sealcrypt/encrypt.hpp
    include/sealcrypt/decrypt.hpp
    include/sealcrypt/file_handler.hpp
)

# Create library target
add_library(sealcrypt ${SEALCRYPT_LIB_SOURCES})
add_library(sealcrypt::sealcrypt ALIAS sealcrypt)

# Set include directories and link with SEAL
target_include_directories(sealcrypt
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link against SEAL
target_link_libraries(sealcrypt
    PUBLIC
    SEAL::seal
)

# Create executable if this is the main project
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    add_subdirectory(src)
    add_subdirectory(tests)
endif()

# Installation rules
install(TARGETS sealcrypt
    EXPORT sealcrypt-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION)

install(FILES ${SEALCRYPT_HEADERS}
    DESTINATION include/sealcrypt
)

install(EXPORT sealcrypt-targets
    FILE sealcrypt-targets.cmake
    NAMESPACE sealcrypt::
    DESTINATION lib/cmake/sealcrypt
)

# Create and install package config files
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/sealcrypt-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sealcrypt-config.cmake"
    INSTALL_DESTINATION lib/cmake/sealcrypt
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/sealcrypt-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/sealcrypt-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/sealcrypt-config-version.cmake"
    DESTINATION lib/cmake/sealcrypt
)
