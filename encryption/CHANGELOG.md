# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-29

### Initial Release

This is the first stable release of the encryption library for Go. This library provides a flexible and secure foundation for implementing encryption in Go applications with built-in security best practices.

### Features

#### Encryption Algorithms
- **AES-256-GCM**: Galois/Counter Mode encryption with 256-bit keys
  - Standard 12-byte nonce size
  - 16-byte authentication tag
  - Hardware acceleration support on modern CPUs
- **ChaCha20-Poly1305**: Stream cipher with authenticated encryption
  - 12-byte nonce size
  - Consistent performance across all CPU architectures
  - No hardware acceleration required
- **XChaCha20-Poly1305**: Extended nonce variant of ChaCha20-Poly1305
  - 24-byte nonce size for safer random nonce generation
  - Ideal for high-throughput scenarios

#### Key Derivation Functions
- **PBKDF2**: Password-Based Key Derivation Function 2
  - Default: 131,072 iterations (OWASP 2023 recommendation)
  - Minimum: 100,000 iterations enforced
  - Configurable hash functions (SHA-1, SHA-256, SHA-512, etc.)
  - Rails ActiveRecord compatible configuration
- **Scrypt**: Memory-hard key derivation function
  - Default: N=2^15, r=8, p=1
  - Configurable CPU/memory cost, block size, and parallelization
  - Protection against hardware-accelerated attacks
- **Argon2id**: Winner of the Password Hashing Competition
  - Default: 64MB memory, 1 iteration, 4 parallelism
  - Configurable time, memory, and parallelism parameters
  - State-of-the-art password hashing
- **HKDF**: HMAC-based Key Derivation Function (RFC 5869)
  - Fast key derivation without iterations
  - Optional info parameter for context-specific keys
  - Auto-generated salt support
  - Support for multiple hash functions

#### Initialization Vector (IV) Generation
- **Deterministic IV**: Consistent IVs for the same input
  - Useful for deterministic encryption
  - Configurable hash function
- **Random IV**: Cryptographically secure random IVs
  - Recommended for most use cases
  - Uses `crypto/rand` for secure randomness

#### Serialization Formats
- **Base64**: Simple base64 encoding
  - URL-safe and standard variants
  - Efficient encoding/decoding
- **Base64 JSON**: Rails-compatible JSON format
  - Includes metadata in JSON structure
  - Compatible with Rails ActiveRecord encryption
- **Base85**: Most efficient format
  - Higher density than Base64
  - Not URL-safe

#### Security Features
- **Associated Authenticated Data (AAD)**: Optional AAD support for all AEAD ciphers
  - Authenticate metadata without encrypting it
  - Prevents tampering with context information
  - Full support in all cipher implementations
- **Key Rotation**: Built-in support for key rotation
  - Encrypt with current key, decrypt with multiple keys
  - Seamless key migration
  - Automatic key fallback during rotation
- **Security Validation**: Enforced minimum security parameters
  - Minimum key length: 16 bytes (128 bits)
  - Minimum PBKDF2 iterations: 100,000
  - Minimum salt length: 8 bytes
  - Empty key detection
- **Zeroization**: Secure memory clearing
  - Automatic key zeroization support
  - Prevents sensitive data from remaining in memory
  - Constant-time key comparison to prevent timing attacks

### Security

- All ciphers use authenticated encryption (AEAD)
- Enforced minimum security parameters
- Constant-time operations where applicable
- Secure random number generation
- Memory zeroization support
- Protection against timing attacks

### Performance

- Comprehensive benchmark suite included
- Performance metrics for all ciphers
- Data size scaling benchmarks
- Key rotation performance analysis
- Memory allocation tracking

### Testing

- **Unit Tests**: Comprehensive test coverage
  - Edge cases (empty plaintext, very large data)
  - Concurrent access testing
  - Key rotation scenarios
  - AAD functionality
  - Error handling
- **Benchmarks**: Performance comparison suite
  - All cipher algorithms
  - Different data sizes (64B to 64KB)
  - With and without AAD
  - Key rotation scenarios

### Documentation

- Comprehensive README with examples
- API documentation
- Security best practices guide
- Performance benchmarks documentation
- Rails ActiveRecord compatibility guide

### API

#### Core Components

```go
// Encryptor - High-level encryption interface
type Encryptor struct {
    Cipherer
    Serializer
}

// Cipher - Low-level encryption interface
type Cipherer interface {
    Cipher(ctx context.Context, in []byte, aad []byte) (nonce, cipherText []byte, err error)
    Decipher(ctx context.Context, nonce, cipherText []byte, aad []byte) (out []byte, err error)
    AuthTagSize() int
    NonceSize() int
}

// Key Provider - Key derivation and rotation
type RotatingKeyProvider interface {
    EncryptionKey(ctx context.Context) ([]byte, error)
    DecryptionKeys(ctx context.Context) ([][]byte, error)
}
```

#### Key Features

- **Context Support**: All operations support `context.Context` for cancellation
- **Error Handling**: Comprehensive error types and messages
- **Backward Compatibility**: Existing code continues to work
- **Extensibility**: Interface-based design for custom implementations

### Migration

This is the initial release, so no migration is needed. For future versions, migration guides will be provided here.

### Dependencies

- Go 1.20 or later
- `golang.org/x/crypto` for additional crypto primitives
- Standard library only for core functionality

### Known Issues

None at this time.

### Acknowledgments

- Inspired by Rails' ActiveRecord encryption
- Built with Go's standard crypto packages
- Follows OWASP security recommendations
- Implements RFC standards (HKDF, Argon2, etc.)

### Example Usage

```go
package main

import (
    "context"
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
    key := []byte("your-secure-key-at-least-16-bytes")
    salt := []byte("your-salt-8bytes")
    plainText := []byte("Hello, World!")
    ctx := context.Background()

    // Create key provider
    keyProvider, err := key.NewPBKDF2Provider(
        [][]byte{key},
        salt,
        sha256.New,
        cipher.AES256GCMKeySize,
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create encryptor
    encryptor := encryption.New(
        cipher.NewAES256GCM(
            keyProvider,
            initvector.Deterministic(sha256.New),
        ),
        encoding.NewSimpleBase64(base64.RawStdEncoding),
    )

    // Encrypt
    encrypted, err := encryptor.Encrypt(ctx, plainText)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt
    decrypted, err := encryptor.Decrypt(ctx, encrypted)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Original: %s\nDecrypted: %s\n", plainText, decrypted)
}
```

### Links

- [GitHub Repository](https://github.com/kikihakiem/playground/encryption)
- [Documentation](https://pkg.go.dev/github.com/kikihakiem/playground/encryption)
- [Issue Tracker](https://github.com/kikihakiem/playground/issues)

---

## [Unreleased]

### Planned Features
- Additional cipher algorithms
- More serialization formats
- Performance optimizations
- Additional key derivation functions

---

[1.0.0]: https://github.com/kikihakiem/playground/encryption/releases/tag/v1.0.0
