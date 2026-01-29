package encoding

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/kikihakiem/playground/encryption"
)

type base64Text struct {
	payload []byte
	encoder *base64.Encoding
}

func (b64 base64Text) MarshalJSON() ([]byte, error) {
	str := b64.encoder.EncodeToString(b64.payload)
	return json.Marshal(str)
}

func (b64 *base64Text) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	decoded, err := b64.encoder.DecodeString(str)
	if err != nil {
		return err
	}

	b64.payload = decoded

	return nil
}

type base64JSON struct {
	Payload base64Text `json:"p"`
	Header  header     `json:"h"`
}

type header struct {
	AuthTag    base64Text `json:"at"`
	InitVector base64Text `json:"iv"`
}

func newBase64JSON(nonce, payload, authTag []byte, encoder *base64.Encoding) base64JSON {
	return base64JSON{
		Payload: base64Text{payload: payload, encoder: encoder},
		Header: header{
			InitVector: base64Text{payload: nonce, encoder: encoder},
			AuthTag:    base64Text{payload: authTag, encoder: encoder},
		},
	}
}

// JSONBase64Serializer implements Serializer using JSON with Base64 encoding.
// This format is compatible with Rails ActiveRecord encryption.
type JSONBase64Serializer struct {
	*base64.Encoding
}

// NewJSONBase64 creates a new JSONBase64Serializer with the given encoding.
func NewJSONBase64(enc *base64.Encoding) *JSONBase64Serializer {
	return &JSONBase64Serializer{enc}
}

// Serialize encodes the nonce and ciphertext into a JSON byte slice.
func (j JSONBase64Serializer) Serialize(nonce, cipherText []byte, authTagSize, nonceSize int) ([]byte, error) {
	if len(cipherText) < authTagSize {
		return nil, encryption.ErrTruncated
	}

	obj := newBase64JSON(nonce, cipherText[:len(cipherText)-authTagSize], cipherText[len(cipherText)-authTagSize:], j.Encoding)

	encoded, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}

	return encoded, nil
}

// Deserialize decodes the JSON byte slice into nonce and ciphertext.
func (j JSONBase64Serializer) Deserialize(encoded []byte, authTagSize, nonceSize int) ([]byte, []byte, error) {
	decoded := newBase64JSON(nil, nil, nil, j.Encoding)

	err := json.Unmarshal(encoded, &decoded)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal JSON: %w", err)
	}

	return decoded.Header.InitVector.payload, append(decoded.Payload.payload, decoded.Header.AuthTag.payload...), nil
}
