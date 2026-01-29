package cipher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/kikihakiem/playground/encryption"
)

const (
	// AES256GCMKeySize is the key size for AES-256-GCM in bytes.
	AES256GCMKeySize = 32
)

// AES256GCM implements ciphertext encryption using AES-256-GCM (Galois/Counter Mode).
type AES256GCM struct {
	RotatingKeyProvider
	InitVectorer
	authTagSize int
	nonceSize   int
}

// NewAES256GCM creates a new AES-256-GCM cipher with the provided key provider and IV generator.
func NewAES256GCM(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *AES256GCM {
	return &AES256GCM{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
		authTagSize:         16, // GCM tag size
		nonceSize:           12, // GCM standard nonce size
	}
}

// Cipher encrypts the plaintext using AES-256-GCM with optional associated authenticated data (AAD).
func (c *AES256GCM) Cipher(ctx context.Context, plainText []byte, aad []byte) ([]byte, []byte, error) {
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

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("new GCM: %w", err)
	}

	cipherText := aesgcm.Seal(nil, nonce, plainText, aad)

	return nonce, cipherText, nil
}

// Decipher decrypts the ciphertext using AES-256-GCM with optional associated authenticated data (AAD).
func (c *AES256GCM) Decipher(ctx context.Context, nonce, cipherText []byte, aad []byte) (deciphered []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(nonce) < c.nonceSize || len(cipherText) < c.authTagSize {
		return nil, encryption.ErrTruncated
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

		deciphered, err = c.decipher(key, nonce, cipherText, aad)
		if err == nil {
			return
		}
		lastErr = fmt.Errorf("key %d: %w", i, err)
	}

	return nil, fmt.Errorf("decryption failed with %d key(s): %w", len(decryptionKeys), lastErr)
}

func (c *AES256GCM) decipher(decryptionKey, nonce, cipherText []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherText, aad)
	if err != nil {
		return nil, fmt.Errorf("aesgcm open: %w", err)
	}

	return plaintext, nil
}

// AuthTagSize returns the authentication tag size in bytes.
func (c *AES256GCM) AuthTagSize() int {
	return c.authTagSize
}

// NonceSize returns the nonce size in bytes.
func (c *AES256GCM) NonceSize() int {
	return c.nonceSize
}
