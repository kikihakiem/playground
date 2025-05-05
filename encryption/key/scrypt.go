package key

import "golang.org/x/crypto/scrypt"

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

func ScryptProvider(keys [][]byte, salt []byte, keyLength int, options ...ScryptOption) *scryptProvider {
	provider := &scryptProvider{
		N: scryptDefaultN,
		r: scryptDefaultR,
		p: scryptDefaultP,
	}

	for _, option := range options {
		option(provider)
	}

	for _, key := range keys {
		derivedKey, err := scrypt.Key(key, salt, provider.N, provider.r, provider.p, keyLength)
		if err != nil {
			continue
		}
		provider.keys = append(provider.keys, derivedKey)
	}

	return provider
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
