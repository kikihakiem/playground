package encryption

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	DefaultIterations = 1 << 16 // = 65536
	DefaultKeySize    = 32
)

type PBKDF2KeyProvider struct {
	Keys                [][]byte
	iterations, keySize int
}

type PBKDF2KeyProviderOption func(*PBKDF2KeyProvider)

func PBKDF2Iterations(n int) PBKDF2KeyProviderOption {
	return func(pkp *PBKDF2KeyProvider) {
		pkp.iterations = n
	}
}

func PBKDF2KeySize(n int) PBKDF2KeyProviderOption {
	return func(pkp *PBKDF2KeyProvider) {
		pkp.keySize = n
	}
}

func NewPBKDF2KeyProvider(plainKeys [][]byte, salt []byte, hashFunc func() hash.Hash, options ...PBKDF2KeyProviderOption) *PBKDF2KeyProvider {
	keyProvider := &PBKDF2KeyProvider{
		iterations: DefaultIterations,
		keySize:    DefaultKeySize,
	}

	for _, option := range options {
		option(keyProvider)
	}

	for _, plainKey := range plainKeys {
		keyProvider.Keys = append(keyProvider.Keys, pbkdf2.Key(
			plainKey,
			salt,
			keyProvider.iterations,
			keyProvider.keySize,
			hashFunc,
		))
	}

	return keyProvider
}

func (kp *PBKDF2KeyProvider) EncryptionKey() []byte {
	return kp.Keys[0] // always encrypt using the latest key
}

func (kp *PBKDF2KeyProvider) DecryptionKeys() [][]byte {
	return kp.Keys
}
