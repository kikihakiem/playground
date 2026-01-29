# Encryption

A flexible and secure text encryption library for Go with configurable ciphers, IV generation, serialization formats, and key rotation capabilities. This library provides a robust foundation for implementing encryption in your Go applications with built-in security best practices. You can also maintain compatibility with Rails' ActiveRecord encryption with [provided configuration below](#rails-activerecord-compatible-encryptor).

## Features

- 🔒 Multiple encryption algorithms:
  - AES-256-GCM
  - ChaCha20-Poly1305
  - XChaCha20-Poly1305
- 🔐 Optional Associated Authenticated Data (AAD) support for all AEAD ciphers
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
    encrypted, err := deterministicEncryptor.Encrypt(context.Background(), plainText)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Decrypt the encrypted text
    decrypted, err := deterministicEncryptor.Decrypt(context.Background(), encrypted)
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

### Using Associated Authenticated Data (AAD)

AAD allows you to authenticate additional data without encrypting it. This is useful for including metadata, context, or headers that need to be authenticated but don't need to be secret:

```go
keyProvider, err := key.NewPBKDF2Provider(
    [][]byte{key},
    salt,
    sha256.New,
    cipher.AES256GCMKeySize,
)
if err != nil {
    panic(err)
}

encryptor := encryption.New(
    cipher.NewAES256GCM(
        keyProvider,
        initvector.Random(),
    ),
    encoding.NewSimpleBase64(base64.RawStdEncoding),
)

// AAD is authenticated but not encrypted
aad := []byte("user-id:12345,tenant:acme")
plainText := []byte("sensitive-data")

// Encrypt with AAD
encrypted, err := encryptor.EncryptWithAAD(ctx, plainText, aad)
if err != nil {
    panic(err)
}

// Decrypt with the same AAD - must match exactly
decrypted, err := encryptor.DecryptWithAAD(ctx, encrypted, aad)
if err != nil {
    panic(err) // Will fail if AAD doesn't match
}
```

**Important**: The AAD used for decryption must exactly match the AAD used for encryption, or decryption will fail.

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

## Performance Benchmarks

The library includes comprehensive benchmarks to help you understand the performance characteristics of different ciphers. Run the benchmarks with:

```bash
go test -tags=benchmark -bench=. -benchmem ./cipher
```

### Available Benchmarks

The benchmark suite includes:

- **Cipher Performance**: Encryption and decryption benchmarks for all supported ciphers
  - AES-256-GCM
  - ChaCha20-Poly1305
  - XChaCha20-Poly1305
- **AAD Performance**: Benchmarks with Associated Authenticated Data
- **Data Size Scaling**: Performance across different data sizes (64B to 64KB)
- **Key Rotation**: Performance impact of key rotation scenarios

### Example Benchmark Output

```
BenchmarkAES256GCM_Encrypt-11                    1000000              1012 ns/op            2944 B/op          9 allocs/op
BenchmarkAES256GCM_Decrypt-11                    2731684               432.7 ns/op          2304 B/op          3 allocs/op
BenchmarkAES256GCM_EncryptWithAAD-11             1000000              1018 ns/op            2944 B/op          9 allocs/op
BenchmarkChaCha20Poly1305_Encrypt-11              686670              1690 ns/op            1696 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_Decrypt-11             1000000              1170 ns/op            1056 B/op          2 allocs/op
BenchmarkXChaCha20Poly1305_Encrypt-11             667482              1784 ns/op            1696 B/op          8 allocs/op
BenchmarkXChaCha20Poly1305_Decrypt-11             958093              1553 ns/op            1056 B/op          2 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_64-11     2162542               560.7 ns/op          1872 B/op          9 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_256-11    1824976               637.4 ns/op          2080 B/op          9 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_1024-11   1000000              1035 ns/op            2944 B/op          9 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_4096-11    447008              2549 ns/op            6656 B/op          9 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_16384-11                   140546              8650 ns/op           20224 B/op          9 allocs/op
BenchmarkAES256GCM_DifferentSizes/Size_65536-11                    36297             32721 ns/op           75520 B/op          9 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_64-11              2392338               495.8 ns/op           624 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_256-11             1502845               792.1 ns/op           832 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_1024-11             685267              1708 ns/op            1696 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_4096-11             222457              5292 ns/op            5408 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_16384-11             61179             19505 ns/op           18976 B/op          8 allocs/op
BenchmarkChaCha20Poly1305_DifferentSizes/Size_65536-11             15590             77472 ns/op           74272 B/op          8 allocs/op
BenchmarkAES256GCM_KeyRotation-11                                1000000              1090 ns/op            4802 B/op         10 allocs/op
```

### Performance Characteristics

**AES-256-GCM:**
- Excellent performance on modern CPUs with AES-NI hardware acceleration
- Lower CPU usage on x86_64 architectures
- Widely supported and standardized

**ChaCha20-Poly1305:**
- Consistent performance across all CPU architectures
- No hardware acceleration required
- Good choice for systems without AES-NI support
- Slightly faster on some ARM processors

**XChaCha20-Poly1305:**
- Similar to ChaCha20-Poly1305 but with extended nonce (24 bytes)
- Better for random nonce generation scenarios
- Slightly slower due to larger nonce size

### Benchmarking Different Data Sizes

To see how performance scales with data size:

```bash
go test -tags=benchmark -bench=BenchmarkAES256GCM_DifferentSizes -benchmem ./cipher
go test -tags=benchmark -bench=BenchmarkChaCha20Poly1305_DifferentSizes -benchmem ./cipher
```

This will show performance metrics for data sizes ranging from 64 bytes to 64KB, helping you understand the overhead and throughput characteristics for your specific use case.

### Key Rotation Performance

Benchmark key rotation scenarios:

```bash
go test -tags=benchmark -bench=BenchmarkAES256GCM_KeyRotation -benchmem ./cipher
```

This benchmark measures the performance impact when decrypting with multiple keys (simulating key rotation scenarios).

### Tips for Interpreting Benchmarks

1. **ns/op**: Nanoseconds per operation - lower is better
2. **B/op**: Bytes allocated per operation - important for memory-constrained environments
3. **allocs/op**: Number of allocations per operation - fewer allocations reduce GC pressure
4. **Run multiple times**: Use `-count=5` to get more reliable averages
5. **Compare on your hardware**: Performance characteristics can vary significantly between different CPU architectures

### Example: Running Specific Benchmarks

```bash
# Run all benchmarks
go test -tags=benchmark -bench=. -benchmem ./cipher

# Run only encryption benchmarks
go test -tags=benchmark -bench=Encrypt -benchmem ./cipher

# Run with more iterations for better accuracy
go test -tags=benchmark -bench=. -benchmem -count=5 ./cipher

# Run benchmarks for a specific cipher
go test -tags=benchmark -bench=AES256GCM -benchmem ./cipher
```

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
