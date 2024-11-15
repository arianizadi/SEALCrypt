# Executable target
add_executable(sealcrypt_exe main.cpp)
set_target_properties(sealcrypt_exe PROPERTIES OUTPUT_NAME "sealcrypt")

# Link executable with the library
target_link_libraries(sealcrypt_exe PRIVATE sealcrypt)
