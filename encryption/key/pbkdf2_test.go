//go:build unit

package key

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPBKDF2Provider(t *testing.T) {
	salt := []byte("test-salt")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")

	t.Run("custom key size", func(t *testing.T) {
		customSize := 24
		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			customSize,
		)
		require.NoError(t, err)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("custom iterations", func(t *testing.T) {
		// Create two providers with different iterations (both above minimum)
		provider1, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
			PBKDF2Iterations(MinPBKDF2Iterations),
		)
		require.NoError(t, err)

		provider2, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
			PBKDF2Iterations(MinPBKDF2Iterations+10000),
		)
		require.NoError(t, err)

		// Different iterations should produce different keys
		encryptionKey1, err := provider1.EncryptionKey()
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey()
		assert.NoError(t, err)
		assert.NotEqual(t, encryptionKey1, encryptionKey2)
	})

	t.Run("multiple options", func(t *testing.T) {
		customSize := 24
		customIterations := MinPBKDF2Iterations

		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			customSize,
			PBKDF2Iterations(customIterations),
		)
		require.NoError(t, err)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("multiple keys", func(t *testing.T) {
		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1, plainKey2},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

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
		provider1, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Same input should produce same key
		encryptionKey1, err := provider1.EncryptionKey()
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey()
		assert.NoError(t, err)
		assert.Equal(t, encryptionKey1, encryptionKey2)
	})

	t.Run("no key", func(t *testing.T) {
		provider, err := NewPBKDF2Provider(
			[][]byte{},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		_, err = provider.EncryptionKey()
		assert.ErrorIs(t, err, ErrNoKey)

		_, err = provider.DecryptionKeys()
		assert.ErrorIs(t, err, ErrNoKey)
	})

	t.Run("validation errors", func(t *testing.T) {
		t.Run("key length too small", func(t *testing.T) {
			_, err := NewPBKDF2Provider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				8, // Below MinKeyLength
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "key length")
		})

		t.Run("salt too short", func(t *testing.T) {
			_, err := NewPBKDF2Provider(
				[][]byte{plainKey1},
				[]byte("short"), // Only 5 bytes
				sha256.New,
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "salt length")
		})

		t.Run("iterations too low", func(t *testing.T) {
			_, err := NewPBKDF2Provider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				32,
				PBKDF2Iterations(1000), // Below MinPBKDF2Iterations
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "iterations")
		})

		t.Run("empty key", func(t *testing.T) {
			_, err := NewPBKDF2Provider(
				[][]byte{[]byte("")},
				salt,
				sha256.New,
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "empty key")
		})
	})
}
