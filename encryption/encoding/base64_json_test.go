//go:build unit

package encoding_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/stretchr/testify/assert"
)

func TestJSONBase64(t *testing.T) {
	base64JSONEncrypted := []byte(`{"p":"lEMctSYVzhJvYJZKTzSsStfbqugE8VTtPj6wBw1x","h":{"iv":"E9qSpdOfUMtrveT/","at":"QaBeEg/rnKGEjzi1sciVoQ=="}}`)
	ctx := context.Background()
	t.Run("happy path", func(t *testing.T) {
		encoder := encoding.NewJSONBase64(base64.StdEncoding)

		// Test serialize
		nonce := []byte("test-nonce")
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
		recoveredNonce, recoveredCipherText, err = encoder.Deserialize(ctx, base64JSONEncrypted, authTagSize, nonceSize)
		assert.NoError(t, err)
		assert.NotEmpty(t, recoveredNonce)
		assert.NotEmpty(t, recoveredCipherText)
	})

	t.Run("truncated cipher text", func(t *testing.T) {
		encoder := encoding.NewJSONBase64(base64.RawStdEncoding)

		// Test truncated cipher text
		cipherText := make([]byte, 15)
		_, err := encoder.Serialize(ctx, nil, cipherText, 16, 12)
		assert.ErrorContains(t, err, "truncated")

		// Test empty cipher text
		_, err = encoder.Serialize(ctx, nil, nil, 16, 12)
		assert.ErrorContains(t, err, "truncated")
	})

	t.Run("deserialize errors", func(t *testing.T) {
		encoder := encoding.NewJSONBase64(base64.RawStdEncoding)

		// Test invalid JSON
		_, _, err := encoder.Deserialize(ctx, []byte("aW52YWxpZCBKU09O"), 16, 12)
		assert.ErrorContains(t, err, "invalid")

		// Test malformed JSON
		_, _, err = encoder.Deserialize(ctx, []byte(`{"p":123}`), 16, 12)
		assert.ErrorContains(t, err, "json")

		// Test wrong base64 encoding
		_, _, err = encoder.Deserialize(ctx, base64JSONEncrypted, 16, 12)
		assert.ErrorContains(t, err, "illegal")
	})
}
