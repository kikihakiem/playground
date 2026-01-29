//go:build unit

package cipher_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption"
	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXChaCha20Poly1305(t *testing.T) {
	var (
		xchachaSalt      = []byte("XChaCha20Poly1305TestSalt12345")
		xchachaKey1      = []byte("XChaCha20Poly1305TestKey123456789012")
		xchachaPlainText = []byte("Hello XChaCha20-Poly1305!")
		ctx              = context.Background()
	)

	scryptKeyProvider, err := key.NewScryptProvider(
		[][]byte{xchachaKey1},
		xchachaSalt,
		cipher.ChaCha20Poly1305KeySize,
	)
	require.NoError(t, err)

	deterministicXChaCha := encryption.New(
		cipher.NewXChaCha20Poly1305(
			scryptKeyProvider,
			initvector.Deterministic(sha256.New),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	nonDeterministicXChaCha := encryption.New(
		cipher.NewXChaCha20Poly1305(
			scryptKeyProvider,
			initvector.Random(),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encryption", func(t *testing.T) {
		encrypted1, err := deterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := deterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		decrypted, err := deterministicXChaCha.Decrypt(ctx, encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted)
	})

	t.Run("non-deterministic encryption", func(t *testing.T) {
		encrypted1, err := nonDeterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := nonDeterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		// Non-deterministic encryption should produce different output for same input
		assert.NotEqual(t, encrypted1, encrypted2)

		// Test both encryptions can be decrypted correctly
		decrypted1, err := nonDeterministicXChaCha.Decrypt(ctx, encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted1)

		decrypted2, err := nonDeterministicXChaCha.Decrypt(ctx, encrypted2)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted2)
	})

	t.Run("invalid nonce", func(t *testing.T) {
		encrypted, err := nonDeterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		// Corrupt the nonce portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[0] ^= 0xff // Flip bits in first byte

		// Decryption should fail
		_, err = nonDeterministicXChaCha.Decrypt(ctx, corrupted)
		assert.Error(t, err)
	})

	t.Run("invalid ciphertext", func(t *testing.T) {
		encrypted, err := nonDeterministicXChaCha.Encrypt(ctx, xchachaPlainText)
		assert.NoError(t, err)

		// Corrupt the ciphertext portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)-1] ^= 0xff // Flip bits in last byte

		// Decryption should fail
		_, err = nonDeterministicXChaCha.Decrypt(ctx, corrupted)
		assert.Error(t, err)
	})

	t.Run("AAD support", func(t *testing.T) {
		aad := []byte("additional-authenticated-data")
		plainText := []byte("sensitive-data")

		t.Run("encrypt and decrypt with AAD", func(t *testing.T) {
			encrypted, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)
			assert.NotEmpty(t, encrypted)

			decrypted, err := deterministicXChaCha.DecryptWithAAD(ctx, encrypted, aad)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("decrypt fails with wrong AAD", func(t *testing.T) {
			encrypted, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)

			wrongAAD := []byte("wrong-aad")
			_, err = deterministicXChaCha.DecryptWithAAD(ctx, encrypted, wrongAAD)
			assert.Error(t, err)
		})

		t.Run("decrypt fails with nil AAD when encrypted with AAD", func(t *testing.T) {
			encrypted, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)

			_, err = deterministicXChaCha.DecryptWithAAD(ctx, encrypted, nil)
			assert.Error(t, err)
		})

		t.Run("different AAD produces different ciphertext", func(t *testing.T) {
			aad1 := []byte("aad-1")
			aad2 := []byte("aad-2")

			encrypted1, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, aad1)
			assert.NoError(t, err)

			encrypted2, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, aad2)
			assert.NoError(t, err)

			assert.NotEqual(t, encrypted1, encrypted2)
		})

		t.Run("long AAD", func(t *testing.T) {
			longAAD := make([]byte, 1024)
			for i := range longAAD {
				longAAD[i] = byte(i % 256)
			}

			encrypted, err := deterministicXChaCha.EncryptWithAAD(ctx, plainText, longAAD)
			assert.NoError(t, err)

			decrypted, err := deterministicXChaCha.DecryptWithAAD(ctx, encrypted, longAAD)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})
	})
}
