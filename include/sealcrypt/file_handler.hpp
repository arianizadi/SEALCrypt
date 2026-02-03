#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace sealcrypt {

  /// FileHandler provides consistent file operations across the library.
  /// All methods are static - this class cannot be instantiated.
  class FileHandler {
  public:
    FileHandler() = delete;
    ~FileHandler() = delete;

    // ==================== Byte Vector Operations ====================

    /// Read entire file into a byte vector
    /// @param path Path to the file
    /// @param data Output vector to store file contents
    /// @param error Output string for error messages
    /// @return true if successful
    static auto readFile(const std::string& path,
                         std::vector< std::uint8_t >& data,
                         std::string& error) -> bool;

    /// Write byte vector to file
    /// @param path Path to the file
    /// @param data Data to write
    /// @param error Output string for error messages
    /// @return true if successful
    static auto writeFile(const std::string& path,
                          const std::vector< std::uint8_t >& data,
                          std::string& error) -> bool;

    // ==================== Stream Operations ====================
    // Use these for SEAL objects that need direct stream access

    /// Open a file for binary reading
    /// @param path Path to the file
    /// @param error Output string for error messages
    /// @return Open ifstream, or nullptr on failure
    static auto openForReading(const std::string& path, std::string& error)
        -> std::unique_ptr< std::ifstream >;

    /// Open a file for binary writing
    /// @param path Path to the file
    /// @param error Output string for error messages
    /// @return Open ofstream, or nullptr on failure
    static auto openForWriting(const std::string& path, std::string& error)
        -> std::unique_ptr< std::ofstream >;

    // ==================== Key File Operations ====================
    // Specialized methods for SEAL key files with validation

    /// Read SEAL key from file (with validation)
    /// @param path Path to the key file
    /// @param key_data Output vector to store key data
    /// @param error Output string for error messages
    /// @return true if successful
    static auto readKeyFile(const std::string& path,
                            std::vector< std::uint8_t >& key_data,
                            std::string& error) -> bool;

    /// Write SEAL key to file (with validation)
    /// @param path Path to the key file
    /// @param key_data Key data to write
    /// @param error Output string for error messages
    /// @return true if successful
    static auto writeKeyFile(const std::string& path,
                             const std::vector< std::uint8_t >& key_data,
                             std::string& error) -> bool;

    // ==================== Utility Functions ====================

    /// Get file size in bytes
    /// @param path Path to the file
    /// @return File size, or 0 if file doesn't exist or error
    static auto getFileSize(const std::string& path) -> std::size_t;

    /// Check if file exists
    /// @param path Path to the file
    /// @return true if file exists
    static auto fileExists(const std::string& path) -> bool;
  };

} // namespace sealcrypt
