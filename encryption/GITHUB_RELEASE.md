# 🎉 Encryption Library v1.0.0 - Initial Release

We're thrilled to announce the **first stable release** of the encryption library for Go! This library provides a flexible, secure, and production-ready solution for implementing encryption in Go applications with built-in security best practices.

## ✨ What's Included

### 🔒 Encryption Algorithms
- **AES-256-GCM** - Hardware-accelerated encryption with 256-bit keys
- **ChaCha20-Poly1305** - Consistent performance across all CPU architectures
- **XChaCha20-Poly1305** - Extended nonce variant for high-throughput scenarios

### 🔑 Key Derivation Functions
- **PBKDF2** - Default 131,072 iterations (OWASP 2023 recommendation)
- **Scrypt** - Memory-hard key derivation
- **Argon2id** - State-of-the-art password hashing
- **HKDF** - Fast HMAC-based key derivation (RFC 5869)

### 🔐 Security Features
- ✅ **AAD Support** - Associated Authenticated Data for all AEAD ciphers
- ✅ **Key Rotation** - Seamless key migration with automatic fallback
- ✅ **Zeroization** - Secure memory clearing
- ✅ **Constant-Time Operations** - Protection against timing attacks
- ✅ **Enforced Security Parameters** - Minimum key length, iterations, and salt size

### 📦 Serialization Formats
- Base64 (standard and URL-safe)
- Base64 JSON (Rails compatible)
- Base85 (high efficiency)

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
}
```

## 🔄 Key Rotation

```go
// Encrypt with key1
keyProvider1, _ := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, 32)
encryptor1 := encryption.New(cipher.NewAES256GCM(keyProvider1, ...), ...)
encrypted, _ := encryptor1.Encrypt(ctx, plainText)

// Decrypt with [key2, key1] - automatically tries keys in order
keyProvider2, _ := key.NewPBKDF2Provider([][]byte{key2, key1}, salt, sha256.New, 32)
encryptor2 := encryption.New(cipher.NewAES256GCM(keyProvider2, ...), ...)
decrypted, _ := encryptor2.Decrypt(ctx, encrypted) // ✅ Succeeds with key1
```

## 🔐 AAD (Associated Authenticated Data)

```go
aad := []byte("user-id:12345,tenant:acme")
plainText := []byte("sensitive-data")

// Encrypt with AAD
encrypted, _ := encryptor.EncryptWithAAD(ctx, plainText, aad)

// Decrypt with same AAD - must match exactly
decrypted, _ := encryptor.DecryptWithAAD(ctx, encrypted, aad)
```

## 📊 Performance

Comprehensive benchmark suite included! Run benchmarks with:

```bash
go test -bench=. -benchmem ./cipher
```

Benchmarks cover:
- All cipher algorithms (encryption & decryption)
- Different data sizes (64B to 64KB)
- AAD performance
- Key rotation scenarios

## 🧪 Testing

- ✅ Comprehensive unit test coverage
- ✅ Edge case testing (empty plaintext, large data, concurrent access)
- ✅ Key rotation scenario testing
- ✅ Full benchmark suite

## 📚 Documentation

- 📖 [README.md](README.md) - Complete documentation and examples
- 📝 [CHANGELOG.md](CHANGELOG.md) - Detailed changelog
- 🔗 [GoDoc](https://pkg.go.dev/github.com/kikihakiem/playground/encryption) - API documentation

## 🔒 Security Highlights

- **Enforced Minimums**: 16-byte keys, 100K+ PBKDF2 iterations, 8-byte salts
- **Authenticated Encryption**: All ciphers use AEAD modes
- **Memory Safety**: Zeroization support for sensitive data
- **Timing Attack Protection**: Constant-time operations
- **OWASP Compliant**: Follows 2023 security recommendations

## 📋 Requirements

- Go 1.20 or later
- `golang.org/x/crypto` v0.11.0+

## 🎯 Use Cases

- 🔐 Encrypting sensitive data in applications
- 🔄 Implementing key rotation strategies
- 🚂 Rails ActiveRecord encryption compatibility
- 🛡️ Secure data storage and transmission
- 🔑 Multi-tenant applications with AAD

## 🙏 Acknowledgments

- Inspired by Rails' ActiveRecord encryption
- Built with Go's standard crypto packages
- Follows OWASP security recommendations
- Implements RFC standards (HKDF, Argon2, etc.)

## 📦 Installation

```bash
go get github.com/kikihakiem/playground/encryption
```

## 🐛 Issues & Feedback

Found a bug or have a feature request? Please [open an issue](https://github.com/kikihakiem/playground/issues)!

## 📄 License

MIT License - see LICENSE file for details

---

**Full Changelog**: https://github.com/kikihakiem/playground/encryption/compare/v0.1.0...v1.0.0
