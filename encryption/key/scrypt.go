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

type ScryptOption func(*scryptProvider)

func ScryptN(n int) ScryptOption {
	return func(sp *scryptProvider) {
		sp.N = n
	}
}

func ScryptR(r int) ScryptOption {
	return func(sp *scryptProvider) {
		sp.r = r
	}
}

func ScryptP(p int) ScryptOption {
	return func(sp *scryptProvider) {
		sp.p = p
	}
}

type scryptProvider struct {
	keys [][]byte
	N    int
	r    int
	p    int
}

// ScryptProvider creates a key provider using scrypt key derivation.
// Returns an error if key derivation fails or parameters don't meet minimum security requirements.
func ScryptProvider(keys [][]byte, salt []byte, keyLength int, options ...ScryptOption) (*scryptProvider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt length %d is below minimum 8 bytes", len(salt))
	}

	provider := &scryptProvider{
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

func (p *scryptProvider) EncryptionKey() ([]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys[0], nil
}

func (p *scryptProvider) DecryptionKeys() ([][]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys, nil
}
