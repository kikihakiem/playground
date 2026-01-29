package encryption

import (
	"context"
	"fmt"
)

type Cipherer interface {
	Cipher(ctx context.Context, in []byte) (nonce, cipherText []byte, err error)
	Decipher(ctx context.Context, nonce, cipherText []byte) (out []byte, err error)
	AuthTagSize() int
	NonceSize() int
}

type Serializer interface {
	Serialize(ctx context.Context, nonce, cipherText []byte, authTagSize, nonceSize int) (out []byte, err error)
	Deserialize(ctx context.Context, in []byte, authTagSize, nonceSize int) (nonce, cipherText []byte, err error)
}

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

func (e *Encryptor) Encrypt(ctx context.Context, plainText []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nonce, cipherText, err := e.Cipher(ctx, plainText)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	encrypted, err := e.Serialize(ctx, nonce, cipherText, e.AuthTagSize(), e.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return encrypted, nil
}

func (e *Encryptor) Decrypt(ctx context.Context, encryptedText []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nonce, cipherText, err := e.Deserialize(ctx, encryptedText, e.AuthTagSize(), e.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	plainText, err := e.Decipher(ctx, nonce, cipherText)
	if err != nil {
		return nil, fmt.Errorf("decipher: %w", err)
	}

	return plainText, nil
}
