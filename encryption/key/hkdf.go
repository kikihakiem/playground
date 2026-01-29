package key

import (
	"context"
	"crypto/rand"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// MinHKDFSaltLength is the minimum recommended salt length for HKDF.
	// While HKDF can work without salt, using a salt is recommended for security.
	MinHKDFSaltLength = 8

	// hkdfDefaultSaltLength provides a secure default salt length.
	hkdfDefaultSaltLength = 16
)

// HKDFProvider manages keys derived using HKDF (HMAC-based Key Derivation Function).
type HKDFProvider struct {
	keyStore
	hashFunc func() hash.Hash
	info     []byte
}

// HKDFOption is a function option for configuring HKDFProvider.
type HKDFOption func(*HKDFProvider)

// HKDFInfo sets the optional info parameter for HKDF.
// Info is application-specific context information that can be used to derive
// different keys from the same input keying material.
func HKDFInfo(info []byte) HKDFOption {
	return func(hp *HKDFProvider) {
		hp.info = info
	}
}

// NewHKDFProvider creates a key provider using HKDF key derivation.
// Returns an error if parameters don't meet minimum security requirements.
// If salt is empty or nil, a random salt will be generated.
func NewHKDFProvider(plainKeys [][]byte, salt []byte, hashFunc func() hash.Hash, keyLength int, options ...HKDFOption) (*HKDFProvider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	// Generate salt if not provided
	if len(salt) == 0 {
		salt = make([]byte, hkdfDefaultSaltLength)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
	} else if len(salt) < MinHKDFSaltLength {
		return nil, fmt.Errorf("salt length %d is below minimum %d bytes", len(salt), MinHKDFSaltLength)
	}

	keyProvider := &HKDFProvider{
		hashFunc: hashFunc,
	}

	for _, option := range options {
		option(keyProvider)
	}

	for i, plainKey := range plainKeys {
		if len(plainKey) == 0 {
			return nil, fmt.Errorf("empty key provided at index %d", i)
		}

		// Create HKDF reader
		hkdfReader := hkdf.New(hashFunc, plainKey, salt, keyProvider.info)

		// Derive key
		derivedKey := make([]byte, keyLength)
		if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
			return nil, fmt.Errorf("derive key %d: %w", i, err)
		}

		keyProvider.keyStore.keys = append(keyProvider.keyStore.keys, derivedKey)
	}

	return keyProvider, nil
}

// EncryptionKey returns the primary key used for encryption (the most recent one).
func (hp *HKDFProvider) EncryptionKey(ctx context.Context) ([]byte, error) {
	if len(hp.keyStore.keys) == 0 {
		return nil, ErrNoKey
	}

	return hp.keyStore.keys[0], nil
}

// DecryptionKeys returns all available keys for decryption.
func (hp *HKDFProvider) DecryptionKeys(ctx context.Context) ([][]byte, error) {
	if len(hp.keyStore.keys) == 0 {
		return nil, ErrNoKey
	}

	return hp.keyStore.keys, nil
}
