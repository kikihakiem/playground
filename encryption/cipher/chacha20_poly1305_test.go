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

func TestChaCha20Poly1305(t *testing.T) {
	var (
		chachaSalt      = []byte("ChaCha20Poly1305TestSalt12345")
		chachaKey1      = []byte("ChaCha20Poly1305TestKey123456789012")
		chachaPlainText = []byte("Hello ChaCha20-Poly1305!")
	)

	keyProvider1, err := key.Argon2Provider(
		[][]byte{chachaKey1},
		chachaSalt,
		cipher.ChaCha20Poly1305KeySize,
	)
	if err != nil {
		t.Fatalf("failed to create key provider 1: %v", err)
	}

	deterministicChaCha := encryption.New(
		cipher.ChaCha20Poly1305(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	keyProvider2, err := key.Argon2Provider(
		[][]byte{chachaKey1},
		chachaSalt,
		cipher.ChaCha20Poly1305KeySize,
	)
	if err != nil {
		t.Fatalf("failed to create key provider 2: %v", err)
	}

	nonDeterministicChaCha := encryption.New(
		cipher.ChaCha20Poly1305(
			keyProvider2,
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
		keyProvider, err := key.PBKDF2Provider([][]byte{}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.ChaCha20Poly1305(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		_, _, err = cipher.Cipher([]byte("secret"))
		assert.ErrorIs(t, err, key.ErrNoKey)

		_, err = cipher.Decipher(make([]byte, 12), make([]byte, 16))
		assert.ErrorIs(t, err, key.ErrNoKey)
	})
	t.Run("decrypt with wrong key", func(t *testing.T) {
		plainText := []byte("secret")
		keyProvider1, err := key.PBKDF2Provider([][]byte{chachaKey1}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		cipher1 := cipher.ChaCha20Poly1305(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce, cipherText, err := cipher1.Cipher(plainText)
		assert.NoError(t, err)

		// wrong key
		keyProvider2, err := key.PBKDF2Provider([][]byte{[]byte("wrong key")}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		cipherWithWrongKey := cipher.ChaCha20Poly1305(
			keyProvider2,
			initvector.Deterministic(sha256.New),
		)
		_, err = cipherWithWrongKey.Decipher(nonce, cipherText)
		assert.ErrorContains(t, err, "failed")

		// tampered cipher text
		cipherText[13] = 65
		_, err = cipher1.Decipher(nonce, cipherText)
		assert.ErrorContains(t, err, "failed")
	})
}
