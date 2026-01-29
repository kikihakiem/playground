package encoding

import (
	"encoding/ascii85"
	"fmt"

	"github.com/kikihakiem/playground/encryption"
)

type base85 struct{}

func Base85() *base85 {
	return &base85{}
}

func (b base85) Serialize(nonce, cipherText []byte, authTagSize, nonceSize int) ([]byte, error) {
	cipherTextWithNonce := append(nonce, cipherText...)
	maxLen := ascii85.MaxEncodedLen(len(cipherTextWithNonce)) + 4 // +4 for <~ and ~>
	encoded := make([]byte, maxLen)

	// Add <~ marker
	encoded[0] = '<'
	encoded[1] = '~'

	// Encode the data
	n := ascii85.Encode(encoded[2:], cipherTextWithNonce)

	// Add ~> marker
	encoded[n+2] = '~'
	encoded[n+3] = '>'

	return encoded[:n+4], nil
}

func (b base85) Deserialize(encoded []byte, authTagSize, nonceSize int) ([]byte, []byte, error) {
	// Check for minimum length
	if len(encoded) < 4 {
		return nil, nil, encryption.ErrTruncated
	}

	// Check if we have complete markers
	hasStartMarker := len(encoded) >= 2 && encoded[0] == '<' && encoded[1] == '~'
	hasEndMarker := len(encoded) >= 2 && encoded[len(encoded)-2] == '~' && encoded[len(encoded)-1] == '>'

	// If we have partial markers, it's a truncation error
	if (hasStartMarker && !hasEndMarker) || (!hasStartMarker && hasEndMarker) {
		return nil, nil, encryption.ErrTruncated
	}

	// If we have no markers at all, it's an invalid format
	if !hasStartMarker && !hasEndMarker {
		return nil, nil, fmt.Errorf("invalid ascii85 format: missing <~ or ~> markers")
	}

	// Remove markers
	encoded = encoded[2 : len(encoded)-2]

	maxLen := ascii85.MaxEncodedLen(len(encoded))
	decoded := make([]byte, maxLen)
	n, _, err := ascii85.Decode(decoded, encoded, true)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ascii85: %w", err)
	}

	if n < nonceSize+authTagSize {
		return nil, nil, encryption.ErrTruncated
	}

	return decoded[:nonceSize], decoded[nonceSize:n], nil
}
