# Encryption

A flexible and secure text encryption library for Go with configurable ciphers, IV generation, serialization formats, and key rotation capabilities. This library provides a robust foundation for implementing encryption in your Go applications. You can also maintain compatibility with Rails' ActiveRecord encryption with [provided configuration below](#rails-activerecord-compatibility).

## Features

- 🔒 Multiple encryption algorithms:
  - AES-256-GCM (default)
  - ChaCha20-Poly1305
  - XChaCha20-Poly1305
- 🔄 Configurable IV generation (deterministic or random)
- 🔑 Multiple key derivation functions:
  - PBKDF2 (default)
  - Scrypt
  - Argon2id
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

    // Create a deterministic encryptor with AES-256-GCM
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

### Using Scrypt for Key Derivation

```go
// Create an encryptor using Scrypt for key derivation
scryptEncryptor := encryption.NewEncryptor(
    encryption.NewAES256GCMCipher(
        encryption.NewScryptKeyProvider(
            [][]byte{key},
            salt,
            32, // key length
            encryption.ScryptN(1<<15), // CPU/memory cost
            encryption.ScryptR(8),     // block size
            encryption.ScryptP(1),     // parallelization
        ),
        encryption.NewRandomIVGenerator(),
    ),
    encryption.NewSimpleBase64Encoder(base64.RawStdEncoding),
)
```

### Using ChaCha20-Poly1305

```go
// Create an encryptor using ChaCha20-Poly1305
chachaEncryptor := encryption.NewEncryptor(
    encryption.NewChaCha20Poly1305Cipher(
        encryption.NewPBKDF2KeyProvider(
            [][]byte{key},
            salt,
            sha256.New,
        ),
        encryption.NewRandomIVGenerator(),
    ),
    encryption.NewSimpleBase64Encoder(base64.RawStdEncoding),
)
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
  - PBKDF2: Configurable iterations and hash function
  - Scrypt: Configurable CPU/memory cost, block size, and parallelization
  - Argon2id: Configurable memory size, iterations, and parallelism

### 2. Encoder

The encoder component handles the serialization of encrypted data:

- **Base64**: Simple base64 encoding
- **JSON**: Base64-encoded JSON format with metadata
- **Custom**: Implement your own encoder

## Security Considerations

- Always use cryptographically secure random values for keys and salts
- Choose appropriate parameters for your key derivation function:
  - PBKDF2: Use at least 100,000 iterations
  - Scrypt: N=2^15, r=8, p=1 is a good starting point
  - Argon2id: Use recommended parameters from the Argon2 specification
- Use random IVs unless you specifically need deterministic encryption
- Rotate keys periodically and maintain a history of old keys for decryption
- Store keys securely using a key management service or hardware security module

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Acknowledgments

- Inspired by Rails' ActiveRecord encryption
- Built with Go's standard crypto packages
