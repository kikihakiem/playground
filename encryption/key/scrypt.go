package key

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	// MinScryptN is the minimum recommended CPU/memory cost parameter.
	// Based on OWASP recommendations (2^15 = 32768).
	MinScryptN = 1 << 15

	// MinScryptR is the minimum recommended block size parameter.
	MinScryptR = 8

	// MinScryptP is the minimum recommended parallelization parameter.
	MinScryptP = 1

	scryptDefaultN = 1 << 15
	scryptDefaultR = 8
	scryptDefaultP = 1
)

// ScryptProvider manages keys derived using scrypt.
type ScryptProvider struct {
	keys [][]byte
	N    int
	r    int
	p    int
}

// ScryptOption is a function option for configuring ScryptProvider.
type ScryptOption func(*ScryptProvider)

// ScryptN sets the CPU/memory cost parameter N.
func ScryptN(n int) ScryptOption {
	return func(sp *ScryptProvider) {
		sp.N = n
	}
}

// ScryptR sets the block size parameter r.
func ScryptR(r int) ScryptOption {
	return func(sp *ScryptProvider) {
		sp.r = r
	}
}

// ScryptP sets the parallelization parameter p.
func ScryptP(p int) ScryptOption {
	return func(sp *ScryptProvider) {
		sp.p = p
	}
}

// NewScryptProvider creates a key provider using scrypt key derivation.
// Returns an error if key derivation fails or parameters don't meet minimum security requirements.
func NewScryptProvider(keys [][]byte, salt []byte, keyLength int, options ...ScryptOption) (*ScryptProvider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt length %d is below minimum 8 bytes", len(salt))
	}

	provider := &ScryptProvider{
		N: scryptDefaultN,
		r: scryptDefaultR,
		p: scryptDefaultP,
	}

	for _, option := range options {
		option(provider)
	}

	// Validate parameters after options are applied
	if provider.N < MinScryptN {
		return nil, fmt.Errorf("N parameter %d is below minimum %d", provider.N, MinScryptN)
	}

	if provider.r < MinScryptR {
		return nil, fmt.Errorf("r parameter %d is below minimum %d", provider.r, MinScryptR)
	}

	if provider.p < MinScryptP {
		return nil, fmt.Errorf("p parameter %d is below minimum %d", provider.p, MinScryptP)
	}

	for i, key := range keys {
		if len(key) == 0 {
			return nil, fmt.Errorf("empty key provided at index %d", i)
		}

		derivedKey, err := scrypt.Key(key, salt, provider.N, provider.r, provider.p, keyLength)
		if err != nil {
			return nil, fmt.Errorf("derive key %d: %w", i, err)
		}
		provider.keys = append(provider.keys, derivedKey)
	}

	return provider, nil
}

// EncryptionKey returns the primary key used for encryption (the most recent one).
func (p *ScryptProvider) EncryptionKey() ([]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys[0], nil
}

// DecryptionKeys returns all available keys for decryption.
func (p *ScryptProvider) DecryptionKeys() ([][]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys, nil
}
