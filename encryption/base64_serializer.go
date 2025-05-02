package encryption

import (
	"encoding/base64"
	"fmt"
)

type SimpleBase64 struct {
	*base64.Encoding
}

func NewSimpleBase64Encoder(enc *base64.Encoding) *SimpleBase64 {
	return &SimpleBase64{enc}
}

func (s SimpleBase64) Serialize(nonce, cipherText []byte, authTagSize, nonceSize int) ([]byte, error) {
	cipherTextWithNonce := append(nonce, cipherText...)
	encoded := make([]byte, s.EncodedLen(len(cipherTextWithNonce)))
	s.Encode(encoded, cipherTextWithNonce)

	return encoded, nil
}

func (s SimpleBase64) Deserialize(encoded []byte, authTagSize, nonceSize int) ([]byte, []byte, error) {
	decoded := make([]byte, s.DecodedLen(len(encoded)))
	n, err := s.Decode(decoded, encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode base64: %w", err)
	}

	if n < nonceSize+authTagSize {
		return nil, nil, ErrTruncated
	}

	return decoded[:nonceSize], decoded[nonceSize:], nil
}
