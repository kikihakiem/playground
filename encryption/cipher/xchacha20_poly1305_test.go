//go:build unit

package cipher_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption"
	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
	"github.com/stretchr/testify/assert"
)

func TestXChaCha20Poly1305(t *testing.T) {
	var (
		xchachaSalt      = []byte("XChaCha20Poly1305TestSalt12345")
		xchachaKey1      = []byte("XChaCha20Poly1305TestKey123456789012")
		xchachaPlainText = []byte("Hello XChaCha20-Poly1305!")
	)

	deterministicXChaCha := encryption.New(
		cipher.XChaCha20Poly1305(
			key.ScryptProvider(
				[][]byte{xchachaKey1},
				xchachaSalt,
				cipher.ChaCha20Poly1305KeySize,
			),
			initvector.Deterministic(sha256.New),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	nonDeterministicXChaCha := encryption.New(
		cipher.XChaCha20Poly1305(
			key.ScryptProvider(
				[][]byte{xchachaKey1},
				xchachaSalt,
				cipher.ChaCha20Poly1305KeySize,
			),
			initvector.Random(),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encryption", func(t *testing.T) {
		encrypted1, err := deterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := deterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		decrypted, err := deterministicXChaCha.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted)
	})

	t.Run("non-deterministic encryption", func(t *testing.T) {
		encrypted1, err := nonDeterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := nonDeterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		// Non-deterministic encryption should produce different output for same input
		assert.NotEqual(t, encrypted1, encrypted2)

		// Test both encryptions can be decrypted correctly
		decrypted1, err := nonDeterministicXChaCha.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted1)

		decrypted2, err := nonDeterministicXChaCha.Decrypt(encrypted2)
		assert.NoError(t, err)
		assert.Equal(t, xchachaPlainText, decrypted2)
	})

	t.Run("invalid nonce", func(t *testing.T) {
		encrypted, err := nonDeterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		// Corrupt the nonce portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[0] ^= 0xff // Flip bits in first byte

		// Decryption should fail
		_, err = nonDeterministicXChaCha.Decrypt(corrupted)
		assert.Error(t, err)
	})

	t.Run("invalid ciphertext", func(t *testing.T) {
		encrypted, err := nonDeterministicXChaCha.Encrypt(xchachaPlainText)
		assert.NoError(t, err)

		// Corrupt the ciphertext portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)-1] ^= 0xff // Flip bits in last byte

		// Decryption should fail
		_, err = nonDeterministicXChaCha.Decrypt(corrupted)
		assert.Error(t, err)
	})
}
