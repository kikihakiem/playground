# v1.0.0 - Initial Release

First stable release of the encryption library for Go! A flexible, secure, and production-ready solution for implementing encryption with built-in security best practices.

## Highlights

### Encryption Algorithms
- **AES-256-GCM** - Hardware-accelerated with 256-bit keys
- **ChaCha20-Poly1305** - Consistent cross-platform performance
- **XChaCha20-Poly1305** - Extended nonce for high-throughput

### Key Derivation
- **PBKDF2** (default: 131,072 iterations)
- **Scrypt** - Memory-hard derivation
- **Argon2id** - State-of-the-art hashing
- **HKDF** - Fast HMAC-based derivation

### Security Features
- AAD (Associated Authenticated Data) support
- Key rotation with automatic fallback
- Secure memory zeroization
- Constant-time operations
- Enforced security minimums (16-byte keys, 100K+ iterations)

### Serialization
- Base64 (standard & URL-safe)
- Base64 JSON (Rails compatible)
- Base85 (high efficiency)

## Quick Start

```bash
go get github.com/kikihakiem/playground/encryption
```

```go
keyProvider, _ := key.NewPBKDF2Provider(
    [][]byte{key}, salt, sha256.New, cipher.AES256GCMKeySize,
)
encryptor := encryption.New(
    cipher.NewAES256GCM(keyProvider, initvector.Deterministic(sha256.New)),
    encoding.NewSimpleBase64(base64.RawStdEncoding),
)
encrypted, _ := encryptor.Encrypt(ctx, []byte("Hello, World!"))
```

## Benchmarks Included

```bash
go test -bench=. -benchmem ./cipher
```

## Documentation

- [README](README.md) - Complete guide
- [CHANGELOG](CHANGELOG.md) - Full changelog
- [GoDoc](https://pkg.go.dev/github.com/kikihakiem/playground/encryption) - API docs

## Security

- OWASP 2023 compliant
- Enforced minimum security parameters
- Authenticated encryption (AEAD)
- Timing attack protection

---

**Full Changelog**: https://github.com/kikihakiem/playground/encryption/compare/v0.1.0...v1.0.0
