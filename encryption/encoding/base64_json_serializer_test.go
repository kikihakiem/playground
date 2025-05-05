//go:build unit

package encoding_test

import (
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption/encoding"
	"github.com/stretchr/testify/assert"
)

var base64JSONEncrypted = []byte(`{"p":"lEMctSYVzhJvYJZKTzSsStfbqugE8VTtPj6wBw1x","h":{"iv":"E9qSpdOfUMtrveT/","at":"QaBeEg/rnKGEjzi1sciVoQ=="}}`)

func TestTruncatedCipherText(t *testing.T) {
	cipherText := make([]byte, 15)

	encoder := encoding.JSONBase64(base64.RawStdEncoding)
	_, err := encoder.Serialize(nil, cipherText, 16, 12)
	assert.ErrorContains(t, err, "truncated")
}

func TestInvalidJSON(t *testing.T) {
	encoder := encoding.JSONBase64(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize([]byte("aW52YWxpZCBKU09O"), 16, 12)
	assert.ErrorContains(t, err, "invalid")
}

func TestWrongEncoding2(t *testing.T) {
	encoder := encoding.JSONBase64(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize(base64JSONEncrypted, 16, 12)
	assert.ErrorContains(t, err, "illegal")
}
