//go:build benchmark

package cipher_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
)

var (
	benchSalt      = []byte("BenchmarkTestSalt12345678901234567890")
	benchKey       = []byte("BenchmarkTestKey12345678901234567890")
	benchPlainText = make([]byte, 1024) // 1KB
	benchAAD       = make([]byte, 256)  // 256 bytes
	benchCtx       = context.Background()
)

func init() {
	// Initialize test data
	for i := range benchPlainText {
		benchPlainText[i] = byte(i % 256)
	}
	for i := range benchAAD {
		benchAAD[i] = byte(i % 256)
	}
}

func setupAES256GCM() (*cipher.AES256GCM, error) {
	keyProvider, err := key.NewPBKDF2Provider([][]byte{benchKey}, benchSalt, sha256.New, cipher.AES256GCMKeySize)
	if err != nil {
		return nil, err
	}
	return cipher.NewAES256GCM(keyProvider, initvector.Deterministic(sha256.New)), nil
}

func setupChaCha20Poly1305() (*cipher.ChaCha20Poly1305, error) {
	keyProvider, err := key.NewPBKDF2Provider([][]byte{benchKey}, benchSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
	if err != nil {
		return nil, err
	}
	return cipher.NewChaCha20Poly1305(keyProvider, initvector.Deterministic(sha256.New)), nil
}

func setupXChaCha20Poly1305() (*cipher.ChaCha20Poly1305, error) {
	keyProvider, err := key.NewPBKDF2Provider([][]byte{benchKey}, benchSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
	if err != nil {
		return nil, err
	}
	return cipher.NewXChaCha20Poly1305(keyProvider, initvector.Deterministic(sha256.New)), nil
}

// BenchmarkAES256GCM_Encrypt benchmarks AES-256-GCM encryption
func BenchmarkAES256GCM_Encrypt(b *testing.B) {
	c, err := setupAES256GCM()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Cipher(benchCtx, benchPlainText, nil)
		if err != nil {
			b.Fatalf("encryption failed: %v", err)
		}
	}
}

// BenchmarkAES256GCM_Decrypt benchmarks AES-256-GCM decryption
func BenchmarkAES256GCM_Decrypt(b *testing.B) {
	c, err := setupAES256GCM()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	nonce, cipherText, err := c.Cipher(benchCtx, benchPlainText, nil)
	if err != nil {
		b.Fatalf("setup encryption failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := c.Decipher(benchCtx, nonce, cipherText, nil)
		if err != nil {
			b.Fatalf("decryption failed: %v", err)
		}
	}
}

// BenchmarkAES256GCM_EncryptWithAAD benchmarks AES-256-GCM encryption with AAD
func BenchmarkAES256GCM_EncryptWithAAD(b *testing.B) {
	c, err := setupAES256GCM()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Cipher(benchCtx, benchPlainText, benchAAD)
		if err != nil {
			b.Fatalf("encryption failed: %v", err)
		}
	}
}

// BenchmarkChaCha20Poly1305_Encrypt benchmarks ChaCha20-Poly1305 encryption
func BenchmarkChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := setupChaCha20Poly1305()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Cipher(benchCtx, benchPlainText, nil)
		if err != nil {
			b.Fatalf("encryption failed: %v", err)
		}
	}
}

// BenchmarkChaCha20Poly1305_Decrypt benchmarks ChaCha20-Poly1305 decryption
func BenchmarkChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := setupChaCha20Poly1305()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	nonce, cipherText, err := c.Cipher(benchCtx, benchPlainText, nil)
	if err != nil {
		b.Fatalf("setup encryption failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := c.Decipher(benchCtx, nonce, cipherText, nil)
		if err != nil {
			b.Fatalf("decryption failed: %v", err)
		}
	}
}

// BenchmarkXChaCha20Poly1305_Encrypt benchmarks XChaCha20-Poly1305 encryption
func BenchmarkXChaCha20Poly1305_Encrypt(b *testing.B) {
	c, err := setupXChaCha20Poly1305()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := c.Cipher(benchCtx, benchPlainText, nil)
		if err != nil {
			b.Fatalf("encryption failed: %v", err)
		}
	}
}

// BenchmarkXChaCha20Poly1305_Decrypt benchmarks XChaCha20-Poly1305 decryption
func BenchmarkXChaCha20Poly1305_Decrypt(b *testing.B) {
	c, err := setupXChaCha20Poly1305()
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}

	nonce, cipherText, err := c.Cipher(benchCtx, benchPlainText, nil)
	if err != nil {
		b.Fatalf("setup encryption failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := c.Decipher(benchCtx, nonce, cipherText, nil)
		if err != nil {
			b.Fatalf("decryption failed: %v", err)
		}
	}
}

// Benchmark comparison for different data sizes
func BenchmarkAES256GCM_DifferentSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384, 65536} // 64B, 256B, 1KB, 4KB, 16KB, 64KB

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		c, err := setupAES256GCM()
		if err != nil {
			b.Fatalf("setup failed: %v", err)
		}

		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, err := c.Cipher(benchCtx, data, nil)
				if err != nil {
					b.Fatalf("encryption failed: %v", err)
				}
			}
		})
	}
}

// Benchmark comparison for different data sizes with ChaCha20-Poly1305
func BenchmarkChaCha20Poly1305_DifferentSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384, 65536}

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		c, err := setupChaCha20Poly1305()
		if err != nil {
			b.Fatalf("setup failed: %v", err)
		}

		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, err := c.Cipher(benchCtx, data, nil)
				if err != nil {
					b.Fatalf("encryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkAES256GCM_KeyRotation benchmarks decryption with key rotation
func BenchmarkAES256GCM_KeyRotation(b *testing.B) {
	key1 := []byte("Key1ForRotationBenchmark123456789012")
	key2 := []byte("Key2ForRotationBenchmark123456789012")

	// Encrypt with key1
	keyProvider1, err := key.NewPBKDF2Provider([][]byte{key1}, benchSalt, sha256.New, cipher.AES256GCMKeySize)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	c1 := cipher.NewAES256GCM(keyProvider1, initvector.Deterministic(sha256.New))
	nonce, cipherText, err := c1.Cipher(benchCtx, benchPlainText, nil)
	if err != nil {
		b.Fatalf("setup encryption failed: %v", err)
	}

	// Decrypt with [key2, key1] - simulates key rotation
	keyProvider2, err := key.NewPBKDF2Provider([][]byte{key2, key1}, benchSalt, sha256.New, cipher.AES256GCMKeySize)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	c2 := cipher.NewAES256GCM(keyProvider2, initvector.Deterministic(sha256.New))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := c2.Decipher(benchCtx, nonce, cipherText, nil)
		if err != nil {
			b.Fatalf("decryption failed: %v", err)
		}
	}
}
