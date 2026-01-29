//go:build unit

package encoding_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/stretchr/testify/assert"
)

func TestSimpleBase64(t *testing.T) {
	base64Encrypted := []byte("/reSGhsM//F08/shs6lWNlhJbaiFlVdyfp/IM8uayQ/l3Wl+xeG/NNScfmWBCLXfGrzANfYfeFiJsHSu28c5")
	ctx := context.Background()
	t.Run("happy path", func(t *testing.T) {
		encoder := encoding.NewSimpleBase64(base64.RawStdEncoding)

		// Test serialize
		nonce := []byte("test-nonce12")
		cipherText := []byte("test-cipher-text-with-auth-tag")
		authTagSize := 16
		nonceSize := 12

		serialized, err := encoder.Serialize(ctx, nonce, cipherText, authTagSize, nonceSize)
		assert.NoError(t, err)

		// Test deserialize
		recoveredNonce, recoveredCipherText, err := encoder.Deserialize(ctx, serialized, authTagSize, nonceSize)
		assert.NoError(t, err)
		assert.Equal(t, nonce, recoveredNonce)
		assert.Equal(t, cipherText, recoveredCipherText)

		// Test deserialize known value
		recoveredNonce, recoveredCipherText, err = encoder.Deserialize(ctx, base64Encrypted, authTagSize, nonceSize)
		assert.NoError(t, err)
		assert.NotEmpty(t, recoveredNonce)
		assert.NotEmpty(t, recoveredCipherText)
	})

	t.Run("truncated encrypted text", func(t *testing.T) {
		encoder := encoding.NewSimpleBase64(base64.RawStdEncoding)
		_, _, err := encoder.Deserialize(ctx, base64Encrypted[:15], 16, 12)
		assert.ErrorContains(t, err, "truncated")
	})

	t.Run("wrong encoding", func(t *testing.T) {
		encoder := encoding.NewSimpleBase64(base64.RawStdEncoding)
		_, _, err := encoder.Deserialize(ctx, []byte("QaBeEg/rnKGEjzi1sciVoQ=="), 16, 12)
		assert.ErrorContains(t, err, "illegal")
	})
}
