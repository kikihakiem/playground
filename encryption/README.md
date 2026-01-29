# Encryption

A flexible and secure text encryption library for Go with configurable ciphers, IV generation, serialization formats, and key rotation capabilities. This library provides a robust foundation for implementing encryption in your Go applications with built-in security best practices. You can also maintain compatibility with Rails' ActiveRecord encryption with [provided configuration below](#rails-activerecord-compatible-encryptor).

## Features

- 🔒 Multiple encryption algorithms:
  - AES-256-GCM
  - ChaCha20-Poly1305
  - XChaCha20-Poly1305
- 🔄 Configurable IV generation (deterministic or random)
- 🔑 Multiple key derivation functions:
  - PBKDF2 (default: 131,072 iterations)
  - Scrypt
  - Argon2id
- 📦 Multiple serialization formats:
  - Base64
  - Base64 JSON (Rails compatible format)
  - Base85
- 🛡️ Built-in security validation:
  - Minimum key lengths (16 bytes)
  - Minimum PBKDF2 iterations (100,000)
  - Minimum salt length (8 bytes)
  - Empty key detection
- 🚂 Rails ActiveRecord encryption compatibility
- 🛠️ Extensible architecture for custom implementations

## Installation

```bash
go get github.com/kikihakiem/playground/encryption
```

## Security Best Practices

This library enforces security best practices by default:

- **PBKDF2 Iterations**: Minimum 100,000 iterations (OWASP 2023 recommendation)
- **Key Length**: Minimum 16 bytes (128 bits)
- **Salt Length**: Minimum 8 bytes
- **Default Iterations**: 131,072 for PBKDF2

These validations help prevent weak encryption configurations. All key providers return errors if parameters don't meet minimum security requirements.

## Quick Start

### Basic Usage

```go
package main

import (
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "log"
    "github.com/kikihakiem/playground/encryption"
    "github.com/kikihakiem/playground/encryption/cipher"
    "github.com/kikihakiem/playground/encryption/encoding"
    "github.com/kikihakiem/playground/encryption/initvector"
    "github.com/kikihakiem/playground/encryption/key"
)

func main() {
    // Define your encryption parameters
    key := []byte("your-secure-key-at-least-16-bytes") // Must be at least 16 bytes
    salt := []byte("your-salt-8bytes")                  // Must be at least 8 bytes
    plainText := []byte("Hello, World!")

    // Create key provider with error handling
    keyProvider, err := key.NewPBKDF2Provider(
        [][]byte{key},
        salt,
        sha256.New,
        cipher.AES256GCMKeySize,
    )
    if err != nil {
        log.Fatalf("Failed to create key provider: %v", err)
    }

    // Create a deterministic encryptor with AES-256-GCM
    deterministicEncryptor := encryption.New(
        cipher.NewAES256GCM(
            keyProvider,
            initvector.Deterministic(sha256.New),
        ),
        encoding.NewSimpleBase64(base64.RawStdEncoding),
    )

    // Encrypt the plain text
    encrypted, err := deterministicEncryptor.Encrypt(plainText)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Decrypt the encrypted text
    decrypted, err := deterministicEncryptor.Decrypt(encrypted)
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }

    fmt.Printf("Original: %s\nDecrypted: %s\n", plainText, decrypted)
}
```

### Using Argon2 or Scrypt Key Provider

Scrypt key provider with its options:

```go
scryptKeyProvider, err := key.NewScryptProvider(
    [][]byte{key},
    salt,
    32, // key length
    key.ScryptN(1<<15), // CPU/memory cost
    key.ScryptR(8),     // block size
    key.ScryptP(1),     // parallelization
)
if err != nil {
    panic(err)
}
```

Argon2 key provider with its options:

```go
argon2KeyProvider, err := key.NewArgon2Provider(
    [][]byte{key},
    salt,
    32,
    key.Argon2Time(1),
    key.Argon2Memory(64*1024),
    key.Argon2Parallelism(4),
)
if err != nil {
    panic(err)
}
```

### Using Extended ChaCha20-Poly1305

```go
argon2KeyProvider, err := key.NewArgon2Provider([][]byte{key}, salt, cipher.ChaCha20Poly1305KeySize)
if err != nil {
    panic(err)
}

xChachaEncryptor := encryption.New(
    cipher.NewXChaCha20Poly1305(
        argon2KeyProvider,
        initvector.Random(),
    ),
    encoding.NewSimpleBase64(base64.RawStdEncoding),
)
```

### Rails ActiveRecord Compatible Encryptor

```go
pbkdf2KeyProvider, err := key.NewPBKDF2Provider(
    [][]byte{key},
    salt,
    sha1.New,
    cipher.AES256GCMKeySize,
    key.PBKDF2Iterations(1<<16),
)
if err != nil {
    panic(err)
}

railsCompatibleEncryptor := encryption.New(
    cipher.NewAES256GCM(
        pbkdf2KeyProvider,
        initvector.Random(),
    ),
    encoding.NewJSONBase64(base64.StdEncoding),
)
```

## Architecture

The library is built with a modular architecture consisting of two main components:

### 1. Cipher

The cipher component handles the core encryption/decryption operations:

- **IV Generator**: Creates initialization vectors (nonces)
  - `Deterministic`: Generates consistent IVs for the same input. Accepts a hash function as parameter.
  - `Random`: Generates cryptographically secure random IVs.
- **Key Provider**: Manages encryption keys and rotation
  - PBKDF2: Configurable iterations and hash function.
  - Scrypt: Configurable CPU/memory cost, block size, and parallelization.
  - Argon2id: Configurable memory size, iterations, and parallelism.

### 2. Encoder

The encoder component handles the serialization of encrypted data:

- **Base64**: Simple base64 encoding
- **Base64 JSON**: Base64-encoded JSON format with metadata
- **Base85**: Most efficient format, but not URL-safe

## Security Considerations

- Always use cryptographically secure random values for keys and salts
- Choose appropriate parameters for your key derivation function:
  - PBKDF2: Use at least 100,000 iterations
  - Scrypt: N=2^15, r=8, p=1 is a good starting point
  - Argon2id: Use recommended parameters from the Argon2 specification
- Use random IVs unless you specifically need deterministic encryption
- Rotate keys periodically and maintain a history of old keys for decryption
- When rotating keys, re-encrypt all existing data with the new key and remove old keys as soon as possible
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
