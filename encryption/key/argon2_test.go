//go:build unit

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2Provider(t *testing.T) {
	salt := []byte("test-salt")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")

	t.Run("custom key size", func(t *testing.T) {
		customSize := 24
		provider := Argon2Provider(
			[][]byte{plainKey1},
			salt,
			customSize,
		)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("custom parameters", func(t *testing.T) {
		// Create two providers with different parameters
		provider1 := Argon2Provider(
			[][]byte{plainKey1},
			salt,
			32,
			Argon2Time(1),
			Argon2Memory(64*1024),
			Argon2Parallelism(4),
		)

		provider2 := Argon2Provider(
			[][]byte{plainKey1},
			salt,
			32,
			Argon2Time(2),
			Argon2Memory(128*1024),
			Argon2Parallelism(8),
		)

		// Different parameters should produce different keys
		key1, err := provider1.EncryptionKey()
		assert.NoError(t, err)

		key2, err := provider2.EncryptionKey()
		assert.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("multiple keys", func(t *testing.T) {
		provider := Argon2Provider(
			[][]byte{plainKey1, plainKey2},
			salt,
			32,
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
		provider1 := Argon2Provider(
			[][]byte{plainKey1},
			salt,
			32,
		)

		provider2 := Argon2Provider(
			[][]byte{plainKey1},
			salt,
			32,
		)

		// Same input should produce same key
		encryptionKey1, err := provider1.EncryptionKey()
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey()
		assert.NoError(t, err)
		assert.Equal(t, encryptionKey1, encryptionKey2)
	})

	t.Run("no key", func(t *testing.T) {
		provider := Argon2Provider(
			[][]byte{},
			salt,
			32,
		)

		_, err := provider.EncryptionKey()
		assert.ErrorIs(t, err, ErrNoKey)

		_, err = provider.DecryptionKeys()
		assert.ErrorIs(t, err, ErrNoKey)
	})
}
