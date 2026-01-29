//go:build unit

package encoding_test

import (
	"testing"

	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/stretchr/testify/assert"
)

func TestBase85(t *testing.T) {
	base85Encrypted := []byte("<~6UX@;D/XQ9E&4f4@:X0fDfTD/0JYE+EV:AH~>")

	t.Run("happy path", func(t *testing.T) {
		encoder := encoding.NewBase85()

		// Test serialize
		nonce := []byte("test-nonce12")
		cipherText := []byte("test-cipher-text-with-auth-tag")
		authTagSize := 16
		nonceSize := 12

		serialized, err := encoder.Serialize(nonce, cipherText, authTagSize, nonceSize)
		assert.NoError(t, err)

		// Test deserialize
		recoveredNonce, recoveredCipherText, err := encoder.Deserialize(serialized, authTagSize, nonceSize)
		assert.NoError(t, err)
		assert.Equal(t, nonce, recoveredNonce)
		assert.Equal(t, cipherText, recoveredCipherText)

		// Test deserialize known value
		recoveredNonce, recoveredCipherText, err = encoder.Deserialize(base85Encrypted, authTagSize, nonceSize)
		assert.NoError(t, err)
		assert.NotEmpty(t, recoveredNonce)
		assert.NotEmpty(t, recoveredCipherText)
	})

	t.Run("truncated encrypted text", func(t *testing.T) {
		encoder := encoding.NewBase85()
		_, _, err := encoder.Deserialize(base85Encrypted[:15], 16, 12)
		assert.ErrorContains(t, err, "truncated")
	})

	t.Run("invalid base85 encoding", func(t *testing.T) {
		encoder := encoding.NewBase85()
		_, _, err := encoder.Deserialize([]byte("invalid base85!"), 16, 12)
		assert.Error(t, err)
	})
}
