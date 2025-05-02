//go:build unit

package encryption_test

import (
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/stretchr/testify/assert"
)

func TestTruncatedCipherText(t *testing.T) {
	cipherText := make([]byte, 15)

	encoder := encryption.NewBase64JSONEncoder(base64.RawStdEncoding)
	_, err := encoder.Serialize(nil, cipherText, 16, 12)
	assert.ErrorContains(t, err, "truncated")
}

func TestInvalidJSON(t *testing.T) {
	encoder := encryption.NewBase64JSONEncoder(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize([]byte("aW52YWxpZCBKU09O"), 16, 12)
	assert.ErrorContains(t, err, "invalid")
}

func TestWrongEncoding2(t *testing.T) {
	encoder := encryption.NewBase64JSONEncoder(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize(encryptedText3, 16, 12)
	assert.ErrorContains(t, err, "illegal")
}
