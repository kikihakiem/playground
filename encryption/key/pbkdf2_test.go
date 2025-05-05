//go:build unit

package key

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPBKDF2Provider(t *testing.T) {
	salt := []byte("test-salt")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")

	t.Run("custom key size", func(t *testing.T) {
		customSize := 24
		provider := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			PBKDF2KeySize(customSize),
		)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("custom iterations", func(t *testing.T) {
		// Create two providers with different iterations
		provider1 := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			PBKDF2Iterations(1000),
		)

		provider2 := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			PBKDF2Iterations(2000),
		)

		// Different iterations should produce different keys
		encryptionKey1, err := provider1.EncryptionKey()
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey()
		assert.NoError(t, err)
		assert.NotEqual(t, encryptionKey1, encryptionKey2)
	})

	t.Run("multiple options", func(t *testing.T) {
		customSize := 24
		customIterations := 1000

		provider := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			PBKDF2KeySize(customSize),
			PBKDF2Iterations(customIterations),
		)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("multiple keys", func(t *testing.T) {
		provider := PBKDF2Provider(
			[][]byte{plainKey1, plainKey2},
			salt,
			sha256.New,
		)

		// Should have 2 decryption keys
		decryptionKeys, err := provider.DecryptionKeys()
		assert.NoError(t, err)
		assert.Len(t, decryptionKeys, 2)

		// Encryption key should be the first key
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Equal(t, decryptionKeys[0], encryptionKey)

		// Keys should be different
		assert.NotEqual(t, decryptionKeys[0], decryptionKeys[1])
	})

	t.Run("derived keys should be consistent", func(t *testing.T) {
		provider1 := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
		)

		provider2 := PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
		)

		// Same input should produce same key
		encryptionKey1, err := provider1.EncryptionKey()
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey()
		assert.NoError(t, err)
		assert.Equal(t, encryptionKey1, encryptionKey2)
	})
}
