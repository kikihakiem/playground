//go:build unit

package key_test

import (
	"crypto/sha256"
	"testing"

	"github.com/bobobox-id/go-library/encryption/key"
	"github.com/stretchr/testify/assert"
)

func TestPBKDF2Provider(t *testing.T) {
	salt := []byte("test-salt")
	plainKey1 := []byte("key1")
	plainKey2 := []byte("key2")

	t.Run("multiple keys", func(t *testing.T) {
		provider := key.PBKDF2Provider(
			[][]byte{plainKey1, plainKey2},
			salt,
			sha256.New,
		)

		// Should have 2 decryption keys
		decryptionKeys := provider.DecryptionKeys()
		assert.Len(t, decryptionKeys, 2)

		// Encryption key should be the first key
		assert.Equal(t, decryptionKeys[0], provider.EncryptionKey())

		// Keys should be different
		assert.NotEqual(t, decryptionKeys[0], decryptionKeys[1])
	})

	t.Run("derived keys should be consistent", func(t *testing.T) {
		provider1 := key.PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
		)

		provider2 := key.PBKDF2Provider(
			[][]byte{plainKey1},
			salt,
			sha256.New,
		)

		// Same input should produce same key
		assert.Equal(t, provider1.EncryptionKey(), provider2.EncryptionKey())
	})
}
