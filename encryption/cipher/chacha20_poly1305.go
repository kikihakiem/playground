package cipher

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305KeySize = chacha20poly1305.KeySize
)

type aead func(key []byte) (cipher.AEAD, error)

type chaCha20Poly1305 struct {
	rotatingKeyProvider
	initVectorer
	authTagSize int
	nonceSize   int
	cipher      aead
}

func ChaCha20Poly1305(keyProvider rotatingKeyProvider, ivGenerator initVectorer) *chaCha20Poly1305 {
	return &chaCha20Poly1305{
		rotatingKeyProvider: keyProvider,
		initVectorer:        ivGenerator,
		authTagSize:         chacha20poly1305.Overhead,
		nonceSize:           chacha20poly1305.NonceSize, // ChaCha20-Poly1305 standard nonce size
		cipher:              chacha20poly1305.New,
	}
}

func (c *chaCha20Poly1305) Cipher(plainText []byte) ([]byte, []byte, error) {
	encryptionKey, err := c.EncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("get encryption key: %w", err)
	}

	nonce, err := c.InitVector(encryptionKey, plainText, c.nonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	aead, err := c.cipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)

	return nonce, cipherText, nil
}

func (c *chaCha20Poly1305) Decipher(nonce, cipherText []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.nonceSize)
	}

	decryptionKeys, err := c.DecryptionKeys()
	if err != nil {
		return nil, fmt.Errorf("get decryption keys: %w", err)
	}

	for _, key := range decryptionKeys {
		aead, err := c.cipher(key)
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

func (c *chaCha20Poly1305) AuthTagSize() int {
	return c.authTagSize
}

func (c *chaCha20Poly1305) NonceSize() int {
	return c.nonceSize
}
