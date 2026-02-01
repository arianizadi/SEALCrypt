#include "sealcrypt/decrypt.hpp"
#include "sealcrypt/encrypt.hpp"

#include <iostream>
#include <string>
#include <vector>

auto main(int argc, char* argv[]) -> int {
  if(argc < 2) {
    std::cout << "Usage:\n"
              << "  " << argv[0]
              << " encrypt --input <file> --output <file> --public-key <key>\n"
              << "  " << argv[0]
              << " decrypt --input <file> --output <file> --private-key <key>\n"
              << "  " << argv[0]
              << " generate-keys --public-key <key> --private-key <key>\n"
              << "\n"
              << "Examples:\n"
              << "  " << argv[0]
              << " encrypt --input input.txt --output output.encrypted "
                 "--public-key public.key\n"
              << "  " << argv[0]
              << " decrypt --input output.encrypted --output decrypted.txt "
                 "--private-key private.key\n"
              << "  " << argv[0]
              << " generate-keys --public-key public.key --private-key "
                 "private.key\n";
    return 1;
  }

  std::vector<std::string> args;
  for(int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  const std::string command = args[0];

  if(command == "encrypt") {
    std::string input_path, output_path, public_key_path;
    bool found_input = false, found_output = false, found_key = false;

    for(std::size_t i = 1; i < args.size(); ++i) {
      if(args[i] == "--input" && i + 1 < args.size()) {
        input_path = args[i + 1];
        found_input = true;
      } else if(args[i] == "--output" && i + 1 < args.size()) {
        output_path = args[i + 1];
        found_output = true;
      } else if(args[i] == "--public-key" && i + 1 < args.size()) {
        public_key_path = args[i + 1];
        found_key = true;
      }
    }

    if(!found_input || !found_output || !found_key) {
      std::cerr << "Error: encrypt command requires --input, --output, and "
                   "--public-key arguments\n";
      return 1;
    }

    sealcrypt::Encryptor encryptor;
    if(!encryptor.init()) {
      std::cerr << "Error initializing encryptor: " << encryptor.getLastError()
                << std::endl;
      return 1;
    }

    if(!encryptor.encryptFile(input_path, output_path, public_key_path)) {
      std::cerr << "Error encrypting file: " << encryptor.getLastError()
                << std::endl;
      return 1;
    }

    std::cout << "Successfully encrypted " << input_path << " to "
              << output_path << std::endl;
    return 0;
  } else if(command == "decrypt") {
    std::string input_path, output_path, private_key_path;
    bool found_input = false, found_output = false, found_key = false;

    for(std::size_t i = 1; i < args.size(); ++i) {
      if(args[i] == "--input" && i + 1 < args.size()) {
        input_path = args[i + 1];
        found_input = true;
      } else if(args[i] == "--output" && i + 1 < args.size()) {
        output_path = args[i + 1];
        found_output = true;
      } else if(args[i] == "--private-key" && i + 1 < args.size()) {
        private_key_path = args[i + 1];
        found_key = true;
      }
    }

    if(!found_input || !found_output || !found_key) {
      std::cerr << "Error: decrypt command requires --input, --output, and "
                   "--private-key arguments\n";
      return 1;
    }

    sealcrypt::Decryptor decryptor;
    if(!decryptor.init()) {
      std::cerr << "Error initializing decryptor: " << decryptor.getLastError()
                << std::endl;
      return 1;
    }

    if(!decryptor.decryptFile(input_path, output_path, private_key_path)) {
      std::cerr << "Error decrypting file: " << decryptor.getLastError()
                << std::endl;
      return 1;
    }

    std::cout << "Successfully decrypted " << input_path << " to "
              << output_path << std::endl;
    return 0;
  } else if(command == "generate-keys") {
    std::string public_key_path, private_key_path;
    bool found_public = false, found_private = false;

    for(std::size_t i = 1; i < args.size(); ++i) {
      if(args[i] == "--public-key" && i + 1 < args.size()) {
        public_key_path = args[i + 1];
        found_public = true;
      } else if(args[i] == "--private-key" && i + 1 < args.size()) {
        private_key_path = args[i + 1];
        found_private = true;
      }
    }

    if(!found_public || !found_private) {
      std::cerr << "Error: generate-keys command requires --public-key and "
                   "--private-key arguments\n";
      return 1;
    }

    sealcrypt::Encryptor encryptor;
    if(!encryptor.init()) {
      std::cerr << "Error initializing encryptor: " << encryptor.getLastError()
                << std::endl;
      return 1;
    }

    if(!encryptor.generateKeys(public_key_path, private_key_path)) {
      std::cerr << "Error generating keys: " << encryptor.getLastError()
                << std::endl;
      return 1;
    }

    std::cout << "Successfully generated keys:\n"
              << "  Public key: " << public_key_path << "\n"
              << "  Private key: " << private_key_path << std::endl;
    return 0;
  } else {
    std::cerr << "Error: Unknown command '" << command << "'\n\n";
    std::cout << "Usage:\n"
              << "  " << argv[0]
              << " encrypt --input <file> --output <file> --public-key <key>\n"
              << "  " << argv[0]
              << " decrypt --input <file> --output <file> --private-key <key>\n"
              << "  " << argv[0]
              << " generate-keys --public-key <key> --private-key <key>\n";
    return 1;
  }
}