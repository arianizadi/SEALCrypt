#include "sealcrypt/file_handler.hpp"

#include <filesystem>
#include <fstream>

namespace sealcrypt {

  auto FileHandler::readFile(const std::string& path,
                             std::vector< std::uint8_t >& data,
                             std::string& error) -> bool {
    try {
      std::ifstream file(path, std::ios::binary);
      if(!file.is_open()) {
        error = "Could not open file for reading: " + path;
        return false;
      }

      // Get file size
      file.seekg(0, std::ios::end);
      const auto size = file.tellg();
      file.seekg(0, std::ios::beg);

      // Read file content
      data.resize(size);
      file.read(reinterpret_cast< char* >(data.data()), size);

      if(!file) {
        error = "Error reading file: " + path;
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      error = "Exception while reading file: " + std::string(e.what());
      return false;
    }
  }

  auto FileHandler::writeFile(const std::string& path,
                              const std::vector< std::uint8_t >& data,
                              std::string& error) -> bool {
    try {
      std::ofstream file(path, std::ios::binary);
      if(!file.is_open()) {
        error = "Could not open file for writing: " + path;
        return false;
      }

      file.write(reinterpret_cast< const char* >(data.data()), data.size());

      if(!file) {
        error = "Error writing to file: " + path;
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      error = "Exception while writing file: " + std::string(e.what());
      return false;
    }
  }

  auto FileHandler::readKeyFile(const std::string& path,
                                std::vector< std::uint8_t >& key_data,
                                std::string& error) -> bool {
    // For key files, we'll add some basic validation
    if(!fileExists(path)) {
      error = "Key file does not exist: " + path;
      return false;
    }

    bool result = readFile(path, key_data, error);
    if(!result) {
      return false;
    }

    // Add any key-specific validation here if needed
    if(key_data.empty()) {
      error = "Key file is empty: " + path;
      return false;
    }

    return true;
  }

  auto FileHandler::writeKeyFile(const std::string& path,
                                 const std::vector< std::uint8_t >& key_data,
                                 std::string& error) -> bool {
    if(key_data.empty()) {
      error = "Cannot write empty key data";
      return false;
    }

    // Add any additional key data validation here

    // Use restricted permissions for key file
    try {
      std::ofstream file(path, std::ios::binary);
      if(!file.is_open()) {
        error = "Could not open key file for writing: " + path;
        return false;
      }

      file.write(reinterpret_cast< const char* >(key_data.data()),
                 key_data.size());

      if(!file) {
        error = "Error writing to key file: " + path;
        return false;
      }

      // On Unix-like systems, you might want to set file permissions here
      // using chmod or similar functionality

      return true;
    } catch(const std::exception& e) {
      error = "Exception while writing key file: " + std::string(e.what());
      return false;
    }
  }

  auto FileHandler::getFileSize(const std::string& path) -> std::size_t {
    try {
      return std::filesystem::file_size(path);
    } catch(...) {
      return 0;
    }
  }

  auto FileHandler::fileExists(const std::string& path) -> bool {
    try {
      return std::filesystem::exists(path);
    } catch(...) {
      return false;
    }
  }

} // namespace sealcrypt