//go:build unit

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScryptProvider(t *testing.T) {
	salt := []byte("test-salt")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")

	t.Run("custom key size", func(t *testing.T) {
		customSize := 24
		provider, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
			customSize,
		)
		require.NoError(t, err)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey()
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("custom parameters", func(t *testing.T) {
		// Create two providers with different parameters
		provider1, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
			32,
			ScryptN(1<<15),
			ScryptR(8),
			ScryptP(1),
		)
		require.NoError(t, err)

		provider2, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
			32,
			ScryptN(1<<16),
			ScryptR(16),
			ScryptP(2),
		)
		require.NoError(t, err)

		// Different parameters should produce different keys
		key1, err := provider1.EncryptionKey()
		assert.NoError(t, err)

		key2, err := provider2.EncryptionKey()
		assert.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("multiple keys", func(t *testing.T) {
		provider, err := NewScryptProvider(
			[][]byte{plainKey1, plainKey2},
			salt,
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
		provider1, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
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
		provider, err := NewScryptProvider(
			[][]byte{},
			salt,
			32,
		)
		require.NoError(t, err)

		_, err = provider.EncryptionKey()
		assert.ErrorIs(t, err, ErrNoKey)

		_, err = provider.DecryptionKeys()
		assert.ErrorIs(t, err, ErrNoKey)
	})

	t.Run("invalid r*p returns error", func(t *testing.T) {
		// Set r and p values that when multiplied exceed 1073741824 (2^30)
		// This will cause scrypt.Key() to fail and ScryptProvider should return an error
		_, err := NewScryptProvider(
			[][]byte{plainKey1},
			salt,
			32,
			ScryptR(32768), // 2^15
			ScryptP(32768), // 2^15
		)

		// Should return an error from ScryptProvider now
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "derive key")
	})

	t.Run("validation errors", func(t *testing.T) {
		t.Run("key length too small", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{plainKey1},
				salt,
				8, // Below MinKeyLength
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "key length")
		})

		t.Run("salt too short", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{plainKey1},
				[]byte("short"), // Only 5 bytes
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "salt length")
		})

		t.Run("N parameter too low", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{plainKey1},
				salt,
				32,
				ScryptN(1024), // Below MinScryptN
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "N parameter")
		})

		t.Run("r parameter too low", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{plainKey1},
				salt,
				32,
				ScryptR(4), // Below MinScryptR
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "r parameter")
		})

		t.Run("p parameter too low", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{plainKey1},
				salt,
				32,
				ScryptP(0), // Below MinScryptP
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "p parameter")
		})

		t.Run("empty key", func(t *testing.T) {
			_, err := NewScryptProvider(
				[][]byte{[]byte("")},
				salt,
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "empty key")
		})
	})
}
