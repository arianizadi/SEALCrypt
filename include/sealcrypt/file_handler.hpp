#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sealcrypt {

  class FileHandler {
  public:
    FileHandler() = delete;
    ~FileHandler() = delete;

    // Read entire file into memory
    static auto readFile(const std::string& path,
                         std::vector< std::uint8_t >& data,
                         std::string& error) -> bool;

    // Write data to file
    static auto writeFile(const std::string& path,
                          const std::vector< std::uint8_t >& data,
                          std::string& error) -> bool;

    // Read SEAL key from file
    static auto readKeyFile(const std::string& path,
                            std::vector< std::uint8_t >& key_data,
                            std::string& error) -> bool;

    // Write SEAL key to file
    static auto writeKeyFile(const std::string& path,
                             const std::vector< std::uint8_t >& key_data,
                             std::string& error) -> bool;

    // Get file size
    static auto getFileSize(const std::string& path) -> std::size_t;

    // Check if file exists
    static auto fileExists(const std::string& path) -> bool;
  };

} // namespace sealcrypt