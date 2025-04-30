# Encryption

A flexible and secure text encryption library for Go with configurable ciphers, IV generation, serialization formats, and key rotation capabilities. This library provides a robust foundation for implementing encryption in your Go applications. You can also maintain compatibility with Rails' ActiveRecord encryption with [provided configuration below](#rails-activerecord-compatibility).

## Features

- 🔒 AES-256-GCM encryption for strong security
- 🔄 Configurable IV generation (deterministic or random)
- 🔑 Key rotation support using PBKDF2
- 📦 Multiple serialization formats (Base64, JSON)
- 🚂 Rails ActiveRecord encryption compatibility
- 🛠️ Extensible architecture for custom implementations

## Installation

```bash
go get github.com/kikihakiem/playground/encryption
```

## Quick Start

### Basic Usage

```go
package main

import (
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "github.com/kikihakiem/playground/encryption"
)

func main() {
    // Define your encryption parameters
    key := []byte("your-secure-key") // Replace with your secure key
    salt := []byte("your-salt")      // Replace with your salt
    plainText := []byte("Hello, World!")

    // Create a deterministic encryptor
    deterministicEncryptor := encryption.NewEncryptor(
        encryption.NewAES256GCMCipher(
            encryption.NewPBKDF2KeyProvider(
                [][]byte{key},
                salt,
                sha256.New,
                encryption.PBKDF2KeySize(encryption.AES256KeySize),
            ),
            encryption.NewDeterministicIVGenerator(sha256.New),
        ),
        encryption.NewSimpleBase64Encoder(base64.RawStdEncoding),
    )

    // Encrypt the plain text
    encrypted, err := deterministicEncryptor.Encrypt(plainText)
    if err != nil {
        panic(err)
    }

    // Decrypt the encrypted text
    decrypted, err := deterministicEncryptor.Decrypt(encrypted)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Original: %s\nDecrypted: %s\n", plainText, decrypted)
}
```

### Rails ActiveRecord Compatibility

```go
// Create a Rails-compatible encryptor
railsCompatibleEncryptor := encryption.NewEncryptor(
    encryption.NewAES256GCMCipher(
        encryption.NewPBKDF2KeyProvider(
            [][]byte{key},
            salt,
            sha1.New,
            encryption.PBKDF2Iterations(1<<16),
        ),
        encryption.NewRandomIVGenerator(),
    ),
    encryption.NewBase64JSONEncoder(base64.StdEncoding),
)
```

## Architecture

The library is built with a modular architecture consisting of two main components:

### 1. Cipher

The cipher component handles the core encryption/decryption operations:

- **IV Generator**: Creates initialization vectors (nonces)
  - `DeterministicIV`: Generates consistent IVs for the same input
  - `RandomIV`: Generates cryptographically secure random IVs
- **Key Provider**: Manages encryption keys and rotation
  - Uses PBKDF2 for key derivation with configurable iterations and hash function
  - Supports multiple keys for rotation:
    - First key in array is used for encryption
    - All keys are tried in order during decryption
    - Allows seamless migration by adding new key at start of array
    - Old data remains decryptable with previous keys
    - After migrating data to new key, old keys can be removed
  - Keys must be ordered from newest (index 0) to oldest
  - Recommended rotation process:
    1. Add new key at start of key array
    2. Deploy new key array to all services
    3. Re-encrypt data with new key (background job)
    4. Remove old keys after migration complete

### 2. Serializer

Handles the conversion of binary ciphertext to various formats:

- **Simple Base64**: Basic Base64 encoding
- **JSON Base64**: Structured format compatible with Rails
- Custom serializers can be implemented by satisfying the `Serializer` interface

## Security Considerations

1. **Key Management**
   - Store keys securely (e.g., using a key management service)
   - Rotate keys regularly
   - Keep only the last 2 keys for rotation
   - Remove old keys after migration

2. **IV Generation**
   - Use `RandomIV` for maximum security
   - Use `DeterministicIV` only when deterministic encryption is required

3. **Key Size**
   - Default key size is 256 bits (AES-256)
   - Do not use smaller key sizes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by Rails' ActiveRecord encryption
- Built with Go's standard crypto packages
