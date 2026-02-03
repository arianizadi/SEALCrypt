#include "sealcrypt/sealcrypt.hpp"

#include <iostream>
#include <string>
#include <vector>

void printUsage(const char* program) {
  std::cout << "SEALCrypt - Homomorphic Encryption Made Simple\n"
            << "\n"
            << "Usage:\n"
            << "  " << program
            << " generate-keys --public <file> --private <file>\n"
            << "  " << program
            << " encrypt --input <file> --output <file> --public-key <key>\n"
            << "  " << program
            << " decrypt --input <file> --output <file> --private-key <key>\n"
            << "\n"
            << "Examples:\n"
            << "  " << program
            << " generate-keys --public pub.key --private priv.key\n"
            << "  " << program
            << " encrypt --input secret.txt --output secret.enc --public-key "
               "pub.key\n"
            << "  " << program
            << " decrypt --input secret.enc --output decrypted.txt "
               "--private-key priv.key\n";
}

auto parseArgs(int argc, char* argv[]) -> std::vector< std::string > {
  std::vector< std::string > args;
  for(int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }
  return args;
}

auto findArg(const std::vector< std::string >& args, const std::string& flag)
    -> std::string {
  for(std::size_t i = 0; i < args.size(); ++i) {
    if(args[i] == flag && i + 1 < args.size()) {
      return args[i + 1];
    }
  }
  return "";
}

auto cmdGenerateKeys(const std::vector< std::string >& args) -> int {
  std::string public_path = findArg(args, "--public");
  std::string private_path = findArg(args, "--private");

  // Support legacy argument names
  if(public_path.empty()) {
    public_path = findArg(args, "--public-key");
  }
  if(private_path.empty()) {
    private_path = findArg(args, "--private-key");
  }

  if(public_path.empty() || private_path.empty()) {
    std::cerr
        << "Error: generate-keys requires --public and --private arguments\n";
    return 1;
  }

  // Create context and generate keys
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << "\n";
    return 1;
  }

  sealcrypt::KeyPair keys(ctx);
  if(!keys.generate()) {
    std::cerr << "Error: " << keys.getLastError() << "\n";
    return 1;
  }

  if(!keys.save(public_path, private_path)) {
    std::cerr << "Error: " << keys.getLastError() << "\n";
    return 1;
  }

  std::cout << "Successfully generated keys:\n"
            << "  Public key:  " << public_path << "\n"
            << "  Private key: " << private_path << "\n";
  return 0;
}

auto cmdEncrypt(const std::vector< std::string >& args) -> int {
  std::string input_path = findArg(args, "--input");
  std::string output_path = findArg(args, "--output");
  std::string public_key_path = findArg(args, "--public-key");

  if(input_path.empty() || output_path.empty() || public_key_path.empty()) {
    std::cerr << "Error: encrypt requires --input, --output, and --public-key "
                 "arguments\n";
    return 1;
  }

  // Create context
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << "\n";
    return 1;
  }

  // Load public key
  sealcrypt::KeyPair keys(ctx);
  if(!keys.loadPublicKey(public_key_path)) {
    std::cerr << "Error: " << keys.getLastError() << "\n";
    return 1;
  }

  // Encrypt file
  sealcrypt::Encryptor encryptor(ctx);
  if(!encryptor.encryptFile(input_path, output_path, keys)) {
    std::cerr << "Error: " << encryptor.getLastError() << "\n";
    return 1;
  }

  std::cout << "Successfully encrypted " << input_path << " to " << output_path
            << "\n";
  return 0;
}

auto cmdDecrypt(const std::vector< std::string >& args) -> int {
  std::string input_path = findArg(args, "--input");
  std::string output_path = findArg(args, "--output");
  std::string private_key_path = findArg(args, "--private-key");

  if(input_path.empty() || output_path.empty() || private_key_path.empty()) {
    std::cerr << "Error: decrypt requires --input, --output, and --private-key "
                 "arguments\n";
    return 1;
  }

  // Create context
  sealcrypt::CryptoContext ctx(sealcrypt::SecurityLevel::Medium);
  if(!ctx.isValid()) {
    std::cerr << "Error: " << ctx.getLastError() << "\n";
    return 1;
  }

  // Load private key
  sealcrypt::KeyPair keys(ctx);
  if(!keys.loadSecretKey(private_key_path)) {
    std::cerr << "Error: " << keys.getLastError() << "\n";
    return 1;
  }

  // Decrypt file
  sealcrypt::Decryptor decryptor(ctx);
  if(!decryptor.decryptFile(input_path, output_path, keys)) {
    std::cerr << "Error: " << decryptor.getLastError() << "\n";
    return 1;
  }

  std::cout << "Successfully decrypted " << input_path << " to " << output_path
            << "\n";
  return 0;
}

auto main(int argc, char* argv[]) -> int {
  if(argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  auto args = parseArgs(argc, argv);
  const std::string& command = args[0];

  if(command == "generate-keys") {
    return cmdGenerateKeys(args);
  }
  if(command == "encrypt") {
    return cmdEncrypt(args);
  }
  if(command == "decrypt") {
    return cmdDecrypt(args);
  }

  std::cerr << "Error: Unknown command '" << command << "'\n\n";
  printUsage(argv[0]);
  return 1;
}
