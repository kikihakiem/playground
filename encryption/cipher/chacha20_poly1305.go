package cipher

import (
	"context"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ChaCha20Poly1305KeySize is the key size for ChaCha20-Poly1305 in bytes.
	ChaCha20Poly1305KeySize = chacha20poly1305.KeySize
)

type aead func(key []byte) (cipher.AEAD, error)

// ChaCha20Poly1305 implements ciphertext encryption using ChaCha20-Poly1305.
type ChaCha20Poly1305 struct {
	RotatingKeyProvider
	InitVectorer
	authTagSize int
	nonceSize   int
	cipher      aead
}

// NewChaCha20Poly1305 creates a new ChaCha20-Poly1305 cipher with the provided key provider and IV generator.
func NewChaCha20Poly1305(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
		authTagSize:         chacha20poly1305.Overhead,
		nonceSize:           chacha20poly1305.NonceSize, // ChaCha20-Poly1305 standard nonce size
		cipher:              chacha20poly1305.New,
	}
}

// Cipher encrypts the plaintext using ChaCha20-Poly1305 with optional associated authenticated data (AAD).
func (c *ChaCha20Poly1305) Cipher(ctx context.Context, plainText []byte, aad []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	encryptionKey, err := c.EncryptionKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("get encryption key: %w", err)
	}

	nonce, err := c.InitVector(ctx, encryptionKey, plainText, c.nonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	aead, err := c.cipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, aad)

	return nonce, cipherText, nil
}

// Decipher decrypts the ciphertext using ChaCha20-Poly1305 with optional associated authenticated data (AAD).
func (c *ChaCha20Poly1305) Decipher(ctx context.Context, nonce, cipherText []byte, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(nonce) != c.nonceSize {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), c.nonceSize)
	}

	decryptionKeys, err := c.DecryptionKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get decryption keys: %w", err)
	}

	var lastErr error
	for i, key := range decryptionKeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		aead, err := c.cipher(key)
		if err != nil {
			lastErr = fmt.Errorf("key %d: create cipher: %w", i, err)
			continue
		}

		plainText, err := aead.Open(nil, nonce, cipherText, aad)
		if err == nil {
			return plainText, nil
		}
		lastErr = fmt.Errorf("key %d: %w", i, err)
	}

	return nil, fmt.Errorf("decryption failed with %d key(s): %w", len(decryptionKeys), lastErr)
}

// AuthTagSize returns the authentication tag size in bytes.
func (c *ChaCha20Poly1305) AuthTagSize() int {
	return c.authTagSize
}

// NonceSize returns the nonce size in bytes.
func (c *ChaCha20Poly1305) NonceSize() int {
	return c.nonceSize
}
