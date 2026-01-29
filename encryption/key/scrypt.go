package key

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
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
// Returns an error if key derivation fails for any of the provided keys.
func ScryptProvider(keys [][]byte, salt []byte, keyLength int, options ...ScryptOption) (*scryptProvider, error) {
	provider := &scryptProvider{
		N: scryptDefaultN,
		r: scryptDefaultR,
		p: scryptDefaultP,
	}

	for _, option := range options {
		option(provider)
	}

	for i, key := range keys {
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
