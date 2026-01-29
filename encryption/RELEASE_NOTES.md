# Release Notes - v1.0.0

**Release Date:** January 29, 2026

We're excited to announce the first stable release of the encryption library for Go! This library provides a flexible, secure, and production-ready solution for implementing encryption in Go applications.

## 🎯 What's New

### Core Features

**Multiple Encryption Algorithms**
- AES-256-GCM with hardware acceleration support
- ChaCha20-Poly1305 for consistent cross-platform performance
- XChaCha20-Poly1305 with extended nonce support

**Key Derivation Functions**
- PBKDF2 with configurable iterations (default: 131,072)
- Scrypt with memory-hard properties
- Argon2id (state-of-the-art password hashing)
- HKDF for fast key derivation

**Security Features**
- Associated Authenticated Data (AAD) support
- Key rotation capabilities
- Secure memory zeroization
- Constant-time operations
- Enforced minimum security parameters

**Serialization Formats**
- Base64 (standard and URL-safe)
- Base64 JSON (Rails compatible)
- Base85 (high efficiency)

## 🔒 Security Highlights

This release includes several security-focused features:

- **Enforced Security Parameters**: Minimum key length (16 bytes), minimum PBKDF2 iterations (100,000), and minimum salt length (8 bytes)
- **Zeroization Support**: Secure memory clearing to prevent sensitive data from remaining in memory
- **Constant-Time Comparison**: Protection against timing attacks
- **Authenticated Encryption**: All ciphers use AEAD modes for both confidentiality and authenticity

## 📊 Performance

The library includes a comprehensive benchmark suite to help you understand performance characteristics:

- All ciphers benchmarked for encryption and decryption
- Performance metrics across different data sizes (64B to 64KB)
- Key rotation performance analysis
- Memory allocation tracking

Run benchmarks with:
```bash
go test -bench=. -benchmem ./cipher
```

## 🧪 Testing

- **Comprehensive Test Coverage**: Edge cases, concurrent access, key rotation scenarios
- **Benchmark Suite**: Performance comparison for all ciphers
- **Error Handling**: Thorough error scenario testing

## 📚 Documentation

- Complete README with examples
- API documentation
- Security best practices guide
- Performance benchmarks documentation
- Rails ActiveRecord compatibility guide

## 🚀 Quick Start

```bash
go get github.com/kikihakiem/playground/encryption
```

```go
package main

import (
    "context"
    "crypto/sha256"
    "encoding/base64"

    "github.com/kikihakiem/playground/encryption"
    "github.com/kikihakiem/playground/encryption/cipher"
    "github.com/kikihakiem/playground/encryption/encoding"
    "github.com/kikihakiem/playground/encryption/initvector"
    "github.com/kikihakiem/playground/encryption/key"
)

func main() {
    key := []byte("your-secure-key-at-least-16-bytes")
    salt := []byte("your-salt-8bytes")

    keyProvider, _ := key.NewPBKDF2Provider(
        [][]byte{key}, salt, sha256.New, cipher.AES256GCMKeySize,
    )

    encryptor := encryption.New(
        cipher.NewAES256GCM(keyProvider, initvector.Deterministic(sha256.New)),
        encoding.NewSimpleBase64(base64.RawStdEncoding),
    )

    encrypted, _ := encryptor.Encrypt(context.Background(), []byte("Hello, World!"))
    decrypted, _ := encryptor.Decrypt(context.Background(), encrypted)
    // ...
}
```

## 🔄 Key Rotation Example

```go
// Encrypt with key1
keyProvider1, _ := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, 32)
encryptor1 := encryption.New(cipher.NewAES256GCM(keyProvider1, ...), ...)
encrypted, _ := encryptor1.Encrypt(ctx, plainText)

// Decrypt with [key2, key1] - automatically tries keys in order
keyProvider2, _ := key.NewPBKDF2Provider([][]byte{key2, key1}, salt, sha256.New, 32)
encryptor2 := encryption.New(cipher.NewAES256GCM(keyProvider2, ...), ...)
decrypted, _ := encryptor2.Decrypt(ctx, encrypted) // Succeeds with key1
```

## 🔐 AAD Support Example

```go
aad := []byte("user-id:12345,tenant:acme")
plainText := []byte("sensitive-data")

// Encrypt with AAD
encrypted, _ := encryptor.EncryptWithAAD(ctx, plainText, aad)

// Decrypt with same AAD - must match exactly
decrypted, _ := encryptor.DecryptWithAAD(ctx, encrypted, aad)
```

## 📋 Requirements

- Go 1.20 or later
- `golang.org/x/crypto` v0.11.0 or later

## 🙏 Acknowledgments

- Inspired by Rails' ActiveRecord encryption
- Built with Go's standard crypto packages
- Follows OWASP security recommendations
- Implements RFC standards (HKDF, Argon2, etc.)

## 📖 Documentation

- [README.md](README.md) - Complete documentation and examples
- [CHANGELOG.md](CHANGELOG.md) - Detailed changelog
- [GoDoc](https://pkg.go.dev/github.com/kikihakiem/playground/encryption) - API documentation

## 🐛 Reporting Issues

If you encounter any issues or have feature requests, please open an issue on GitHub.

## 📄 License

This project is licensed under the MIT License.

---

**Thank you for using the encryption library!** We hope this library helps you build secure applications with confidence.
