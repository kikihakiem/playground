package key

import (
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// MinPBKDF2Iterations is the minimum recommended iterations for PBKDF2.
	// Based on OWASP recommendations (2023).
	MinPBKDF2Iterations = 100_000

	// pbkdf2DefaultIterations provides a secure default (128K iterations).
	pbkdf2DefaultIterations = 1 << 17 // = 131,072

	// MinKeyLength is the minimum recommended key length in bytes.
	MinKeyLength = 16 // 128 bits
)

// PBKDF2Provider manages keys derived using PBKDF2.
type PBKDF2Provider struct {
	keys       [][]byte
	iterations int
}

// PBKDF2Option is a function option for configuring PBKDF2Provider.
type PBKDF2Option func(*PBKDF2Provider)

// PBKDF2Iterations sets the number of iterations for PBKDF2 key derivation.
func PBKDF2Iterations(n int) PBKDF2Option {
	return func(pkp *PBKDF2Provider) {
		pkp.iterations = n
	}
}

// ErrNoKey is returned when no keys are available for encryption or decryption.
var ErrNoKey = errors.New("no key")

// NewPBKDF2Provider creates a key provider using PBKDF2 key derivation.
// Returns an error if parameters don't meet minimum security requirements.
func NewPBKDF2Provider(plainKeys [][]byte, salt []byte, hashFunc func() hash.Hash, keyLength int, options ...PBKDF2Option) (*PBKDF2Provider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt length %d is below minimum 8 bytes", len(salt))
	}

	keyProvider := &PBKDF2Provider{
		iterations: pbkdf2DefaultIterations,
	}

	for _, option := range options {
		option(keyProvider)
	}

	if keyProvider.iterations < MinPBKDF2Iterations {
		return nil, fmt.Errorf("iterations %d is below minimum %d", keyProvider.iterations, MinPBKDF2Iterations)
	}

	for _, plainKey := range plainKeys {
		if len(plainKey) == 0 {
			return nil, fmt.Errorf("empty key provided")
		}

		keyProvider.keys = append(keyProvider.keys, pbkdf2.Key(
			plainKey,
			salt,
			keyProvider.iterations,
			keyLength,
			hashFunc,
		))
	}

	return keyProvider, nil
}

// EncryptionKey returns the primary key used for encryption (the most recent one).
func (kp *PBKDF2Provider) EncryptionKey() ([]byte, error) {
	if len(kp.keys) == 0 {
		return nil, ErrNoKey
	}

	return kp.keys[0], nil // always encrypt using the latest key
}

// DecryptionKeys returns all available keys for decryption.
func (kp *PBKDF2Provider) DecryptionKeys() ([][]byte, error) {
	if len(kp.keys) == 0 {
		return nil, ErrNoKey
	}

	return kp.keys, nil
}
