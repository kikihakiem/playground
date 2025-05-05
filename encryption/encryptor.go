package encryption

import (
	"errors"
	"fmt"
)

type Cipherer interface {
	Cipher(in []byte) (nonce, cipherText []byte, err error)
	Decipher(nonce, cipherText []byte) (out []byte, err error)
	AuthTagSize() int
	NonceSize() int
}

type Serializer interface {
	Serialize(nonce, cipherText []byte, authTagSize, nonceSize int) (out []byte, err error)
	Deserialize(in []byte, authTagSize, nonceSize int) (nonce, cipherText []byte, err error)
}

var ErrTruncated = errors.New("truncated text")

type Encryptor struct {
	Cipherer
	Serializer
}

// New creates a new encryption instance with the given cipher and encoder.
// The cipher is used to encrypt and decrypt the data.
// The encoder is used to encode and decode the data.
func New(cipherer Cipherer, serializer Serializer) *Encryptor {
	return &Encryptor{
		Serializer: serializer,
		Cipherer:   cipherer,
	}
}

func (e *Encryptor) Encrypt(plainText []byte) ([]byte, error) {
	nonce, cipherText, err := e.Cipher(plainText)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	encrypted, err := e.Serialize(nonce, cipherText, e.AuthTagSize(), e.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return encrypted, nil
}

func (e *Encryptor) Decrypt(encryptedText []byte) ([]byte, error) {
	nonce, cipherText, err := e.Deserialize(encryptedText, e.AuthTagSize(), e.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	plainText, err := e.Decipher(nonce, cipherText)
	if err != nil {
		return nil, fmt.Errorf("decipher: %w", err)
	}

	return plainText, nil
}
