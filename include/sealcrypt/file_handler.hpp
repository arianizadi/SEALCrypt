#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sealcrypt {

  class FileHandler {
  public:
    // Read entire file into memory
    static bool readFile(const std::string& path,
                         std::vector< std::uint8_t >& data,
                         std::string& error);

    // Write data to file
    static bool writeFile(const std::string& path,
                          const std::vector< std::uint8_t >& data,
                          std::string& error);

    // Read SEAL key from file
    static bool readKeyFile(const std::string& path,
                            std::vector< std::uint8_t >& key_data,
                            std::string& error);

    // Write SEAL key to file
    static bool writeKeyFile(const std::string& path,
                             const std::vector< std::uint8_t >& key_data,
                             std::string& error);

    // Get file size
    static std::size_t getFileSize(const std::string& path);

    // Check if file exists
    static bool fileExists(const std::string& path);

  private:
    // Utility class - no instantiation
    FileHandler() = delete;
    ~FileHandler() = delete;
  };

} // namespace sealcrypt