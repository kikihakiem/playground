package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

type EncryptionMode int

const (
	AES256GCMKeySize = 32
)

var ErrTruncated = errors.New("truncated text")

type RotatingKeyProvider interface {
	EncryptionKey() []byte
	DecryptionKeys() [][]byte
}

type InitVectorer interface {
	InitVector(key, param []byte, size int) ([]byte, error)
}

type AES256GCM struct {
	RotatingKeyProvider
	InitVectorer
	authTagSize int
	nonceSize   int
}

func CipherAES256GCM(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *AES256GCM {
	return &AES256GCM{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
		authTagSize:         16, // GCM tag size
		nonceSize:           12, // GCM standard nonce size
	}
}

func (c *AES256GCM) Cipher(plainText []byte) ([]byte, []byte, error) {
	encryptionKey := c.EncryptionKey()

	nonce, err := c.InitVector(encryptionKey, plainText, c.nonceSize)
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

	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	return nonce, cipherText, nil
}

func (c *AES256GCM) Decipher(nonce, cipherText []byte) (deciphered []byte, err error) {
	if len(nonce) < c.nonceSize || len(cipherText) < c.authTagSize {
		return nil, ErrTruncated
	}

	for _, key := range c.DecryptionKeys() {
		deciphered, err = c.decipher(key, nonce, cipherText)
		if err == nil {
			return
		}
	}

	return
}

func (c *AES256GCM) decipher(decryptionKey, nonce, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("aesgcm open: %w", err)
	}

	return plaintext, nil
}

func (c *AES256GCM) AuthTagSize() int {
	return c.authTagSize
}

func (c *AES256GCM) NonceSize() int {
	return c.nonceSize
}
