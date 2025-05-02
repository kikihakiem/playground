package encryption

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305KeySize = chacha20poly1305.KeySize
)

type ChaCha20Poly1305 struct {
	RotatingKeyProvider
	InitVectorer
	authTagSize int
	nonceSize   int
}

func NewChaCha20Poly1305Cipher(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
		authTagSize:         chacha20poly1305.Overhead,
		nonceSize:           chacha20poly1305.NonceSize, // ChaCha20-Poly1305 standard nonce size
	}
}

func (c *ChaCha20Poly1305) Cipher(plainText []byte) ([]byte, []byte, error) {
	encryptionKey := c.EncryptionKey()

	nonce, err := c.InitVector(encryptionKey, plainText, c.nonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	aead, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)
	return nonce, cipherText, nil
}

func (c *ChaCha20Poly1305) Decipher(nonce, cipherText []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.nonceSize)
	}

	for _, key := range c.DecryptionKeys() {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			continue
		}

		plainText, err := aead.Open(nil, nonce, cipherText, nil)
		if err == nil {
			return plainText, nil
		}
	}

	return nil, fmt.Errorf("decryption failed")
}

func (c *ChaCha20Poly1305) AuthTagSize() int {
	return c.authTagSize
}

func (c *ChaCha20Poly1305) NonceSize() int {
	return c.nonceSize
}
