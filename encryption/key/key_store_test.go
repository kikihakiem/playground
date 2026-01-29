//go:build unit

package key

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZeroize(t *testing.T) {
	salt := []byte("test-salt-12345678")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")
	ctx := context.Background()

	t.Run("zeroizes single key", func(t *testing.T) {
		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Get the key before zeroization
		keyBefore, err := provider.EncryptionKey(ctx)
		require.NoError(t, err)
		require.NotNil(t, keyBefore)
		require.NotEmpty(t, keyBefore)

		// Verify key has non-zero bytes
		hasNonZero := false
		for _, b := range keyBefore {
			if b != 0 {
				hasNonZero = true
				break
			}
		}
		assert.True(t, hasNonZero, "key should have non-zero bytes before zeroization")

		// Zeroize
		provider.Zeroize()

		// Verify keys slice is nil
		assert.Nil(t, provider.keyStore.keys)

		// Verify EncryptionKey returns error after zeroization
		_, err = provider.EncryptionKey(ctx)
		assert.ErrorIs(t, err, ErrNoKey)

		// Verify DecryptionKeys returns error after zeroization
		_, err = provider.DecryptionKeys(ctx)
		assert.ErrorIs(t, err, ErrNoKey)
	})

	t.Run("zeroizes multiple keys", func(t *testing.T) {
		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1, plainKey2},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Get keys before zeroization
		keysBefore, err := provider.DecryptionKeys(ctx)
		require.NoError(t, err)
		require.Len(t, keysBefore, 2)

		// Verify keys have non-zero bytes
		for _, key := range keysBefore {
			hasNonZero := false
			for _, b := range key {
				if b != 0 {
					hasNonZero = true
					break
				}
			}
			assert.True(t, hasNonZero, "key should have non-zero bytes before zeroization")
		}

		// Zeroize
		provider.Zeroize()

		// Verify keys slice is nil
		assert.Nil(t, provider.keyStore.keys)
	})

	t.Run("zeroizes empty key store", func(t *testing.T) {
		provider := &PBKDF2Provider{
			iterations: MinPBKDF2Iterations,
		}
		// keyStore.keys is already nil/empty

		// Should not panic
		assert.NotPanics(t, func() {
			provider.Zeroize()
		})

		assert.Nil(t, provider.keyStore.keys)
	})

	t.Run("zeroize is idempotent", func(t *testing.T) {
		provider, err := NewPBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
			32,
		)
		require.NoError(t, err)

		// Zeroize multiple times
		provider.Zeroize()
		provider.Zeroize()
		provider.Zeroize()

		// Should still be nil and not panic
		assert.Nil(t, provider.keyStore.keys)
		_, err = provider.EncryptionKey(ctx)
		assert.ErrorIs(t, err, ErrNoKey)
	})
}
