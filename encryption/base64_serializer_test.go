//go:build unit

package encryption_test

import (
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/stretchr/testify/assert"
)

func TestTruncatedEncryptedText(t *testing.T) {
	encoder := encryption.NewSimpleBase64Encoder(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize(encryptedText1[:15], 16, 12)
	assert.ErrorContains(t, err, "truncated")
}

func TestWrongEncoding(t *testing.T) {
	encoder := encryption.NewSimpleBase64Encoder(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize([]byte("QaBeEg/rnKGEjzi1sciVoQ=="), 16, 12)
	assert.ErrorContains(t, err, "illegal")
}
