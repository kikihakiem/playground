package encryption

import (
	"fmt"
)

type Cipherer interface {
	Cipher(in []byte) (nonce, cipherText []byte, err error)
	Decipher(nonce, cipherText []byte) (out []byte, err error)
}

type Serializer interface {
	Serialize(nonce, cipherText []byte) (out []byte, err error)
	Deserialize(in []byte) (nonce, cipherText []byte, err error)
}

type Encryptor struct {
	Cipherer
	Serializer
}

func NewEncryptor(cipherer Cipherer, serializer Serializer) *Encryptor {
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

	encrypted, err := e.Serialize(nonce, cipherText)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return encrypted, nil
}

func (e *Encryptor) Decrypt(encryptedText []byte) ([]byte, error) {
	nonce, cipherText, err := e.Deserialize(encryptedText)
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	plainText, err := e.Decipher(nonce, cipherText)
	if err != nil {
		return nil, fmt.Errorf("decipher: %w", err)
	}

	return plainText, nil
}
