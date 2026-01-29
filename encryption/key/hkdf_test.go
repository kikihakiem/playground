//go:build unit

package key

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHKDFProvider(t *testing.T) {
	salt := []byte("test-salt-12345678")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")
	ctx := context.Background()

	t.Run("custom key size", func(t *testing.T) {
		customSize := 24
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			customSize,
		)
		require.NoError(t, err)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("with info parameter", func(t *testing.T) {
		info := []byte("application-context")
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
			HKDFInfo(info),
		)
		require.NoError(t, err)

		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, 32)
		assert.NotEmpty(t, encryptionKey)
	})

	t.Run("different info produces different keys", func(t *testing.T) {
		info1 := []byte("context-1")
		info2 := []byte("context-2")

		provider1, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
			HKDFInfo(info1),
		)
		require.NoError(t, err)

		provider2, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
			HKDFInfo(info2),
		)
		require.NoError(t, err)

		encryptionKey1, err := provider1.EncryptionKey(ctx)
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.NotEqual(t, encryptionKey1, encryptionKey2, "different info should produce different keys")
	})

	t.Run("multiple options", func(t *testing.T) {
		customSize := 24
		info := []byte("test-info")

		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			customSize,
			HKDFInfo(info),
		)
		require.NoError(t, err)

		// Key should match specified size
		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, customSize)
	})

	t.Run("multiple keys", func(t *testing.T) {
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1, plainKey2},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Should have 2 decryption keys
		decryptionKeys, err := provider.DecryptionKeys(ctx)
		assert.NoError(t, err)
		assert.Len(t, decryptionKeys, 2)

		// Encryption key should be the first key
		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Equal(t, decryptionKeys[0], encryptionKey)

		// Keys should be different
		assert.NotEqual(t, decryptionKeys[0], decryptionKeys[1])
	})

	t.Run("derived keys should be consistent", func(t *testing.T) {
		provider1, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Same input should produce same key
		encryptionKey1, err := provider1.EncryptionKey(ctx)
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Equal(t, encryptionKey1, encryptionKey2)
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		salt1 := []byte("salt-1-12345678")
		salt2 := []byte("salt-2-12345678")

		provider1, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt1,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt2,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		encryptionKey1, err := provider1.EncryptionKey(ctx)
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.NotEqual(t, encryptionKey1, encryptionKey2, "different salts should produce different keys")
	})

	t.Run("auto-generated salt", func(t *testing.T) {
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			nil, // No salt provided, should auto-generate
			sha256.New,
			32,
		)
		require.NoError(t, err)

		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, 32)
		assert.NotEmpty(t, encryptionKey)
	})

	t.Run("empty salt generates random salt", func(t *testing.T) {
		provider1, err := NewHKDFProvider(
			[][]byte{plainKey1},
			[]byte{}, // Empty salt, should auto-generate
			sha256.New,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewHKDFProvider(
			[][]byte{plainKey1},
			[]byte{}, // Empty salt, should auto-generate
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Each should generate different random salts, so keys should be different
		encryptionKey1, err := provider1.EncryptionKey(ctx)
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey(ctx)
		assert.NoError(t, err)
		// Note: There's a very small chance these could be equal, but it's negligible
		// In practice, they will be different due to random salt generation
		assert.NotEqual(t, encryptionKey1, encryptionKey2, "auto-generated salts should produce different keys")
	})

	t.Run("different hash functions", func(t *testing.T) {
		provider1, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		provider2, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha512.New,
			32,
		)
		require.NoError(t, err)

		encryptionKey1, err := provider1.EncryptionKey(ctx)
		assert.NoError(t, err)
		encryptionKey2, err := provider2.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.NotEqual(t, encryptionKey1, encryptionKey2, "different hash functions should produce different keys")
	})

	t.Run("sha1 hash function", func(t *testing.T) {
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha1.New,
			32,
		)
		require.NoError(t, err)

		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, 32)
	})

	t.Run("no key", func(t *testing.T) {
		provider, err := NewHKDFProvider(
			[][]byte{},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		_, err = provider.EncryptionKey(ctx)
		assert.ErrorIs(t, err, ErrNoKey)

		_, err = provider.DecryptionKeys(ctx)
		assert.ErrorIs(t, err, ErrNoKey)
	})

	t.Run("validation errors", func(t *testing.T) {
		t.Run("key length too small", func(t *testing.T) {
			_, err := NewHKDFProvider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				8, // Below MinKeyLength
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "key length")
		})

		t.Run("salt too short", func(t *testing.T) {
			_, err := NewHKDFProvider(
				[][]byte{plainKey1},
				[]byte("short"), // Only 5 bytes, below MinHKDFSaltLength
				sha256.New,
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "salt length")
		})

		t.Run("empty key", func(t *testing.T) {
			_, err := NewHKDFProvider(
				[][]byte{[]byte("")},
				salt,
				sha256.New,
				32,
			)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "empty key")
		})
	})

	t.Run("info parameter variations", func(t *testing.T) {
		t.Run("empty info", func(t *testing.T) {
			provider, err := NewHKDFProvider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				32,
				HKDFInfo([]byte{}),
			)
			require.NoError(t, err)

			encryptionKey, err := provider.EncryptionKey(ctx)
			assert.NoError(t, err)
			assert.Len(t, encryptionKey, 32)
		})

		t.Run("nil info vs empty info", func(t *testing.T) {
			provider1, err := NewHKDFProvider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				32,
				// No info option (nil info)
			)
			require.NoError(t, err)

			provider2, err := NewHKDFProvider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				32,
				HKDFInfo([]byte{}), // Empty info
			)
			require.NoError(t, err)

			// Both should produce the same key (nil and empty are treated the same by HKDF)
			encryptionKey1, err := provider1.EncryptionKey(ctx)
			assert.NoError(t, err)
			encryptionKey2, err := provider2.EncryptionKey(ctx)
			assert.NoError(t, err)
			assert.Equal(t, encryptionKey1, encryptionKey2)
		})

		t.Run("long info parameter", func(t *testing.T) {
			longInfo := make([]byte, 1024)
			for i := range longInfo {
				longInfo[i] = byte(i % 256)
			}

			provider, err := NewHKDFProvider(
				[][]byte{plainKey1},
				salt,
				sha256.New,
				32,
				HKDFInfo(longInfo),
			)
			require.NoError(t, err)

			encryptionKey, err := provider.EncryptionKey(ctx)
			assert.NoError(t, err)
			assert.Len(t, encryptionKey, 32)
		})
	})

	t.Run("large key length", func(t *testing.T) {
		largeKeyLength := 64
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			largeKeyLength,
		)
		require.NoError(t, err)

		encryptionKey, err := provider.EncryptionKey(ctx)
		assert.NoError(t, err)
		assert.Len(t, encryptionKey, largeKeyLength)
	})

	t.Run("zeroize works", func(t *testing.T) {
		provider, err := NewHKDFProvider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		keyBefore, err := provider.EncryptionKey(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, keyBefore)

		provider.Zeroize()

		_, err = provider.EncryptionKey(ctx)
		assert.ErrorIs(t, err, ErrNoKey)
	})
}
