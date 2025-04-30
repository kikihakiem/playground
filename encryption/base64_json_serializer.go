package encryption

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Base64 struct {
	payload []byte
	encoder *base64.Encoding
}

func (b64 Base64) MarshalJSON() ([]byte, error) {
	str := b64.encoder.EncodeToString(b64.payload)
	return json.Marshal(str)
}

func (b64 *Base64) UnmarshalJSON(data []byte) error {
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

type Base64JSON struct {
	Payload Base64 `json:"p"`
	Header  Header `json:"h"`
}

type Header struct {
	AuthTag    Base64 `json:"at"`
	InitVector Base64 `json:"iv"`
}

func newBase64JSON(nonce, payload, authTag []byte, encoder *base64.Encoding) Base64JSON {
	return Base64JSON{
		Payload: Base64{payload: payload, encoder: encoder},
		Header: Header{
			InitVector: Base64{payload: nonce, encoder: encoder},
			AuthTag:    Base64{payload: authTag, encoder: encoder},
		},
	}
}

type Base64JSONEncoder struct {
	*base64.Encoding
}

func NewBase64JSONEncoder(enc *base64.Encoding) *Base64JSONEncoder {
	return &Base64JSONEncoder{enc}
}

func (j Base64JSONEncoder) Serialize(nonce, cipherText []byte) ([]byte, error) {
	if len(cipherText) < AuthTagSize {
		return nil, ErrTruncated
	}

	obj := newBase64JSON(nonce, cipherText[:len(cipherText)-AuthTagSize], cipherText[len(cipherText)-AuthTagSize:], j.Encoding)

	encoded, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}

	return encoded, nil
}

func (j Base64JSONEncoder) Deserialize(encoded []byte) ([]byte, []byte, error) {
	decoded := newBase64JSON(nil, nil, nil, j.Encoding)

	err := json.Unmarshal(encoded, &decoded)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal JSON: %w", err)
	}

	return decoded.Header.InitVector.payload, append(decoded.Payload.payload, decoded.Header.AuthTag.payload...), nil
}
