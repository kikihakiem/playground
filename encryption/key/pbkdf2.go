package key

import (
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2DefaultIterations = 1 << 16 // = 65536
)

type pbkdf2Provider struct {
	keys       [][]byte
	iterations int
}

type PBKDF2KeyProviderOption func(*pbkdf2Provider)

func PBKDF2Iterations(n int) PBKDF2KeyProviderOption {
	return func(pkp *pbkdf2Provider) {
		pkp.iterations = n
	}
}

var ErrNoKey = errors.New("no key")

func PBKDF2Provider(plainKeys [][]byte, salt []byte, hashFunc func() hash.Hash, keySize int, options ...PBKDF2KeyProviderOption) *pbkdf2Provider {
	keyProvider := &pbkdf2Provider{
		iterations: pbkdf2DefaultIterations,
	}

	for _, option := range options {
		option(keyProvider)
	}

	for _, plainKey := range plainKeys {
		keyProvider.keys = append(keyProvider.keys, pbkdf2.Key(
			plainKey,
			salt,
			keyProvider.iterations,
			keySize,
			hashFunc,
		))
	}

	return keyProvider
}

func (kp *pbkdf2Provider) EncryptionKey() ([]byte, error) {
	if len(kp.keys) == 0 {
		return nil, ErrNoKey
	}

	return kp.keys[0], nil // always encrypt using the latest key
}

func (kp *pbkdf2Provider) DecryptionKeys() ([][]byte, error) {
	if len(kp.keys) == 0 {
		return nil, ErrNoKey
	}

	return kp.keys, nil
}
