package encoding

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kikihakiem/playground/encryption"
)

// SimpleBase64 implements Serializer using standard Base64 encoding.
type SimpleBase64 struct {
	*base64.Encoding
}

// NewSimpleBase64 creates a new SimpleBase64 serializer with the given encoding.
func NewSimpleBase64(enc *base64.Encoding) *SimpleBase64 {
	return &SimpleBase64{enc}
}

// Serialize encodes the nonce and ciphertext into a single Base64 byte slice.
func (s SimpleBase64) Serialize(ctx context.Context, nonce, cipherText []byte, authTagSize, nonceSize int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cipherTextWithNonce := append(nonce, cipherText...)
	encoded := make([]byte, s.EncodedLen(len(cipherTextWithNonce)))
	s.Encode(encoded, cipherTextWithNonce)

	return encoded, nil
}

// Deserialize decodes the Base64 byte slice into nonce and ciphertext.
func (s SimpleBase64) Deserialize(ctx context.Context, encoded []byte, authTagSize, nonceSize int) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	decoded := make([]byte, s.DecodedLen(len(encoded)))
	n, err := s.Decode(decoded, encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode base64: %w", err)
	}

	if n < nonceSize+authTagSize {
		return nil, nil, encryption.ErrTruncated
	}

	return decoded[:nonceSize], decoded[nonceSize:n], nil
}
