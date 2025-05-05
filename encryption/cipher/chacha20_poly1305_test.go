//go:build unit

package cipher_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/bobobox-id/go-library/encryption/cipher"
	"github.com/bobobox-id/go-library/encryption/encoding"
	"github.com/bobobox-id/go-library/encryption/initvector"
	"github.com/bobobox-id/go-library/encryption/key"
	"github.com/stretchr/testify/assert"
)

func TestChaCha20Poly1305(t *testing.T) {
	var (
		chachaSalt      = []byte("ChaCha20Poly1305TestSalt12345")
		chachaKey1      = []byte("ChaCha20Poly1305TestKey123456789012")
		chachaPlainText = []byte("Hello ChaCha20-Poly1305!")
	)

	deterministicChaCha := encryption.New(
		cipher.ChaCha20Poly1305(
			key.PBKDF2Provider(
				[][]byte{chachaKey1},
				chachaSalt,
				sha256.New,
				key.PBKDF2KeySize(cipher.ChaCha20Poly1305KeySize),
			),
			initvector.Deterministic(sha256.New),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	nonDeterministicChaCha := encryption.New(
		cipher.ChaCha20Poly1305(
			key.PBKDF2Provider(
				[][]byte{chachaKey1},
				chachaSalt,
				sha256.New,
				key.PBKDF2KeySize(cipher.ChaCha20Poly1305KeySize),
			),
			initvector.Random(),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encryption", func(t *testing.T) {
		encrypted1, err := deterministicChaCha.Encrypt(chachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := deterministicChaCha.Encrypt(chachaPlainText)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		decrypted, err := deterministicChaCha.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted)
	})

	t.Run("non-deterministic encryption", func(t *testing.T) {
		encrypted1, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
		assert.NoError(t, err)

		// Non-deterministic encryption should produce different output for same input
		assert.NotEqual(t, encrypted1, encrypted2)

		// Test both encryptions can be decrypted correctly
		decrypted1, err := nonDeterministicChaCha.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted1)

		decrypted2, err := nonDeterministicChaCha.Decrypt(encrypted2)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted2)
	})

	t.Run("invalid nonce", func(t *testing.T) {
		encrypted, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
		assert.NoError(t, err)

		// Corrupt the nonce portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[0] = ^corrupted[0]

		_, err = nonDeterministicChaCha.Decrypt(corrupted)
		assert.Error(t, err)
	})

	t.Run("no key", func(t *testing.T) {
		cipher := cipher.ChaCha20Poly1305(
			key.PBKDF2Provider([][]byte{}, chachaSalt, sha256.New),
			initvector.Deterministic(sha256.New),
		)

		_, _, err := cipher.Cipher([]byte("secret"))
		assert.ErrorIs(t, err, key.ErrNoKey)

		_, err = cipher.Decipher(make([]byte, 12), make([]byte, 16))
		assert.ErrorIs(t, err, key.ErrNoKey)
	})
}
