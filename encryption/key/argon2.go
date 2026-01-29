package key

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// MinArgon2Memory is the minimum recommended memory in KiB (64 MB).
	// Based on OWASP recommendations.
	MinArgon2Memory = 64 * 1024

	// MinArgon2Time is the minimum recommended number of iterations.
	MinArgon2Time = 1

	// MinArgon2Parallelism is the minimum recommended parallelism.
	MinArgon2Parallelism = 1

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

// Argon2Provider creates a key provider using Argon2id key derivation.
// Returns an error if parameters don't meet minimum security requirements.
func Argon2Provider(keys [][]byte, salt []byte, keyLength int, options ...Argon2Option) (*argon2Provider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt length %d is below minimum 8 bytes", len(salt))
	}

	keyProvider := &argon2Provider{
		time:        argon2DefaultTime,
		memory:      argon2DefaultMemory,
		parallelism: argon2DefaultParallelism,
	}

	for _, option := range options {
		option(keyProvider)
	}

	// Validate parameters after options are applied
	if keyProvider.time < MinArgon2Time {
		return nil, fmt.Errorf("time parameter %d is below minimum %d", keyProvider.time, MinArgon2Time)
	}

	if keyProvider.memory < MinArgon2Memory {
		return nil, fmt.Errorf("memory parameter %d is below minimum %d KiB", keyProvider.memory, MinArgon2Memory)
	}

	if keyProvider.parallelism < MinArgon2Parallelism {
		return nil, fmt.Errorf("parallelism parameter %d is below minimum %d", keyProvider.parallelism, MinArgon2Parallelism)
	}

	for i, key := range keys {
		if len(key) == 0 {
			return nil, fmt.Errorf("empty key provided at index %d", i)
		}

		keyProvider.keys = append(keyProvider.keys, argon2.IDKey(
			key,
			salt,
			keyProvider.time,
			keyProvider.memory,
			keyProvider.parallelism,
			uint32(keyLength),
		))
	}

	return keyProvider, nil
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
