package key

import "golang.org/x/crypto/argon2"

const (
	argon2DefaultMemory      = 64 * 1024
	argon2DefaultTime        = 1
	argon2DefaultParallelism = 4
)

type argon2Provider struct {
	keys        [][]byte
	time        uint32
	memory      uint32
	parallelism uint8
}

type Argon2Option func(*argon2Provider)

func Argon2Time(n int) Argon2Option {
	return func(ap *argon2Provider) {
		ap.time = uint32(n)
	}
}

func Argon2Memory(n int) Argon2Option {
	return func(ap *argon2Provider) {
		ap.memory = uint32(n)
	}
}

func Argon2Parallelism(n int) Argon2Option {
	return func(ap *argon2Provider) {
		ap.parallelism = uint8(n)
	}
}

func Argon2Provider(keys [][]byte, salt []byte, keyLength int, options ...Argon2Option) *argon2Provider {
	keyProvider := &argon2Provider{
		time:        argon2DefaultTime,
		memory:      argon2DefaultMemory,
		parallelism: argon2DefaultParallelism,
	}

	for _, option := range options {
		option(keyProvider)
	}

	for _, key := range keys {
		keyProvider.keys = append(keyProvider.keys, argon2.IDKey(
			key,
			salt,
			keyProvider.time,
			keyProvider.memory,
			keyProvider.parallelism,
			uint32(keyLength),
		))
	}

	return keyProvider
}

func (p *argon2Provider) EncryptionKey() ([]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys[0], nil
}

func (p *argon2Provider) DecryptionKeys() ([][]byte, error) {
	if len(p.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keys, nil
}
