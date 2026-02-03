#include "sealcrypt/file_handler.hpp"

#include <filesystem>

namespace sealcrypt {

  // ==================== Byte Vector Operations ====================

  // TODO: can crash if too large file, implement file streaming? but files can
  // be too large for homomorphic bc of growth potential. Possibly just limit
  // filesize to 1GB?
  auto FileHandler::readFile(const std::string& path,
                             std::vector< std::uint8_t >& data,
                             std::string& error) -> bool {
    try {
      auto file = openForReading(path, error);
      if(!file) {
        return false;
      }

      // Get file size
      file->seekg(0, std::ios::end);
      const auto size = file->tellg();
      file->seekg(0, std::ios::beg);

      // Read file content
      data.resize(static_cast< std::size_t >(size));
      file->read(reinterpret_cast< char* >(data.data()), size);

      if(!*file) {
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
      auto file = openForWriting(path, error);
      if(!file) {
        return false;
      }

      file->write(reinterpret_cast< const char* >(data.data()),
                  static_cast< std::streamsize >(data.size()));

      if(!*file) {
        error = "Error writing to file: " + path;
        return false;
      }

      return true;
    } catch(const std::exception& e) {
      error = "Exception while writing file: " + std::string(e.what());
      return false;
    }
  }

  // ==================== Stream Operations ====================

  auto FileHandler::openForReading(const std::string& path, std::string& error)
      -> std::unique_ptr< std::ifstream > {
    try {
      if(!fileExists(path)) {
        error = "File does not exist: " + path;
        return nullptr;
      }

      auto file = std::make_unique< std::ifstream >(path, std::ios::binary);
      if(!file->is_open()) {
        error = "Could not open file for reading: " + path;
        return nullptr;
      }

      return file;
    } catch(const std::exception& e) {
      error = "Exception while opening file: " + std::string(e.what());
      return nullptr;
    }
  }

  auto FileHandler::openForWriting(const std::string& path, std::string& error)
      -> std::unique_ptr< std::ofstream > {
    try {
      auto file = std::make_unique< std::ofstream >(path, std::ios::binary);
      if(!file->is_open()) {
        error = "Could not open file for writing: " + path;
        return nullptr;
      }

      return file;
    } catch(const std::exception& e) {
      error = "Exception while opening file: " + std::string(e.what());
      return nullptr;
    }
  }

  // ==================== File Operations ====================

  auto FileHandler::readKeyFile(const std::string& path,
                                std::vector< std::uint8_t >& key_data,
                                std::string& error) -> bool {
    if(!fileExists(path)) {
      error = "Key file does not exist: " + path;
      return false;
    }

    if(!readFile(path, key_data, error)) {
      return false;
    }

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

    return writeFile(path, key_data, error);
  }

  // ==================== Utility Functions ====================

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
