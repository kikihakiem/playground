package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	AES256GCMKeySize = 32
)

type aes256GCM struct {
	rotatingKeyProvider
	initVectorer
	authTagSize int
	nonceSize   int
}

func AES256GCM(keyProvider rotatingKeyProvider, ivGenerator initVectorer) *aes256GCM {
	return &aes256GCM{
		rotatingKeyProvider: keyProvider,
		initVectorer:        ivGenerator,
		authTagSize:         16, // GCM tag size
		nonceSize:           12, // GCM standard nonce size
	}
}

func (c *aes256GCM) Cipher(plainText []byte) ([]byte, []byte, error) {
	encryptionKey, err := c.EncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("get encryption key: %w", err)
	}

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

func (c *aes256GCM) Decipher(nonce, cipherText []byte) (deciphered []byte, err error) {
	if len(nonce) < c.nonceSize || len(cipherText) < c.authTagSize {
		return nil, ErrTruncated
	}

	decryptionKeys, err := c.DecryptionKeys()
	if err != nil {
		return nil, fmt.Errorf("get decryption keys: %w", err)
	}

	for _, key := range decryptionKeys {
		deciphered, err = c.decipher(key, nonce, cipherText)
		if err == nil {
			return
		}
	}

	return nil, fmt.Errorf("decryption failed")
}

func (c *aes256GCM) decipher(decryptionKey, nonce, cipherText []byte) ([]byte, error) {
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

func (c *aes256GCM) AuthTagSize() int {
	return c.authTagSize
}

func (c *aes256GCM) NonceSize() int {
	return c.nonceSize
}
