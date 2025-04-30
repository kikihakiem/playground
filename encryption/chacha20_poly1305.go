package encryption

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305KeySize   = 32
	ChaCha20Poly1305NonceSize = chacha20poly1305.NonceSize
)

type ChaCha20Poly1305 struct {
	RotatingKeyProvider
	InitVectorer
}

func NewChaCha20Poly1305Cipher(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
	}
}

func (c *ChaCha20Poly1305) Cipher(plainText []byte) ([]byte, []byte, error) {
	encryptionKey := c.EncryptionKey()

	nonce, err := c.InitVector(encryptionKey, plainText, ChaCha20Poly1305NonceSize)
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
	if len(nonce) != ChaCha20Poly1305NonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), ChaCha20Poly1305NonceSize)
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
