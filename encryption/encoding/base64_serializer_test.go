//go:build unit

package encoding_test

import (
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption/encoding"
	"github.com/stretchr/testify/assert"
)

var base64Encrypted = []byte("/reSGhsM//F08/shs6lWNlhJbaiFlVdyfp/IM8uayQ/l3Wl+xeG/NNScfmWBCLXfGrzANfYfeFiJsHSu28c5")

func TestTruncatedEncryptedText(t *testing.T) {
	encoder := encoding.SimpleBase64(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize(base64Encrypted[:15], 16, 12)
	assert.ErrorContains(t, err, "truncated")
}

func TestWrongEncoding(t *testing.T) {
	encoder := encoding.SimpleBase64(base64.RawStdEncoding)
	_, _, err := encoder.Deserialize([]byte("QaBeEg/rnKGEjzi1sciVoQ=="), 16, 12)
	assert.ErrorContains(t, err, "illegal")
}
