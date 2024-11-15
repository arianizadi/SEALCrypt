#include <filesystem>
#include <fstream>
#include <iostream>
#include <sealcrypt/file_handler.hpp>
#include <string>
#include <vector>

using sealcrypt::FileHandler;

auto test_write_and_read_file() -> bool {
  const std::string test_file = "test_data.bin";
  const std::vector< std::uint8_t > test_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  std::string error;

  // Write test
  if(!FileHandler::writeFile(test_file, test_data, error)) {
    std::cerr << "Write failed: " << error << std::endl;
    return false;
  }

  // Read test
  std::vector< std::uint8_t > read_data;
  if(!FileHandler::readFile(test_file, read_data, error)) {
    std::cerr << "Read failed: " << error << std::endl;
    return false;
  }

  // Compare data
  if(test_data != read_data) {
    std::cerr << "Data mismatch" << std::endl;
    return false;
  }

  // Cleanup
  std::filesystem::remove(test_file);

  return true;
}

auto test_key_file_operations() -> bool {
  const std::string test_key_file = "test_key.bin";
  const std::vector< std::uint8_t > test_key = {0xFF, 0xEE, 0xDD, 0xCC};
  std::string error;

  // Write key test
  if(!FileHandler::writeKeyFile(test_key_file, test_key, error)) {
    std::cerr << "Key write failed: " << error << std::endl;
    return false;
  }

  // Read key test
  std::vector< std::uint8_t > read_key;
  if(!FileHandler::readKeyFile(test_key_file, read_key, error)) {
    std::cerr << "Key read failed: " << error << std::endl;
    return false;
  }

  // Compare keys
  if(test_key != read_key) {
    std::cerr << "Key data mismatch" << std::endl;
    return false;
  }

  // Cleanup
  std::filesystem::remove(test_key_file);
  return true;
}

auto test_file_utilities() -> bool {
  const std::string test_file = "test_util.bin";
  const std::vector< std::uint8_t > test_data = {0x01, 0x02, 0x03};
  std::string error;

  // Test file exists (should not exist yet)
  if(FileHandler::fileExists(test_file)) {
    std::cerr << "File exists when it should not" << std::endl;
    return false;
  }

  // Write file
  if(!FileHandler::writeFile(test_file, test_data, error)) {
    std::cerr << "Write failed: " << error << std::endl;
    return false;
  }

  // Test file exists (should exist now)
  if(!FileHandler::fileExists(test_file)) {
    std::cerr << "File does not exist when it should" << std::endl;
    return false;
  }

  // Test file size
  if(FileHandler::getFileSize(test_file) != test_data.size()) {
    std::cerr << "Incorrect file size" << std::endl;
    return false;
  }

  // Cleanup
  std::filesystem::remove(test_file);
  return true;
}

auto test_error_cases() -> bool {
  std::string error;
  std::vector< std::uint8_t > data;

  // Test reading non-existent file
  if(FileHandler::readFile("nonexistent.bin", data, error)) {
    std::cerr << "Reading non-existent file should fail" << std::endl;
    return false;
  }

  // Test reading empty key file
  const std::string empty_key_file = "empty_key.bin";
  std::ofstream(empty_key_file).close(); // Create empty file

  if(FileHandler::readKeyFile(empty_key_file, data, error)) {
    std::cerr << "Reading empty key file should fail" << std::endl;
    std::filesystem::remove(empty_key_file);
    return false;
  }

  // Cleanup
  std::filesystem::remove(empty_key_file);
  return true;
}

auto main() -> int {
  bool all_passed = true;

  // Run all tests
  all_passed &= test_write_and_read_file();
  all_passed &= test_key_file_operations();
  all_passed &= test_file_utilities();
  all_passed &= test_error_cases();

  if(all_passed) {
    std::cout << "passed" << std::endl;
    return 0;
  } else {
    std::cout << "failed" << std::endl;
    return 1;
  }
}