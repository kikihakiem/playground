package key

import (
	"context"
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

// Argon2Provider manages keys derived using Argon2id.
type Argon2Provider struct {
	keyStore
	time        uint32
	memory      uint32
	parallelism uint8
}

// Argon2Option is a function option for configuring Argon2Provider.
type Argon2Option func(*Argon2Provider)

// Argon2Time sets the time parameter (iterations).
func Argon2Time(n int) Argon2Option {
	return func(ap *Argon2Provider) {
		ap.time = uint32(n)
	}
}

// Argon2Memory sets the memory parameter in KiB.
func Argon2Memory(n int) Argon2Option {
	return func(ap *Argon2Provider) {
		ap.memory = uint32(n)
	}
}

// Argon2Parallelism sets the parallelism parameter.
func Argon2Parallelism(n int) Argon2Option {
	return func(ap *Argon2Provider) {
		ap.parallelism = uint8(n)
	}
}

// NewArgon2Provider creates a key provider using Argon2id key derivation.
// Returns an error if parameters don't meet minimum security requirements.
func NewArgon2Provider(keys [][]byte, salt []byte, keyLength int, options ...Argon2Option) (*Argon2Provider, error) {
	if keyLength < MinKeyLength {
		return nil, fmt.Errorf("key length %d is below minimum %d bytes", keyLength, MinKeyLength)
	}

	if len(salt) < 8 {
		return nil, fmt.Errorf("salt length %d is below minimum 8 bytes", len(salt))
	}

	keyProvider := &Argon2Provider{
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

		keyProvider.keyStore.keys = append(keyProvider.keyStore.keys, argon2.IDKey(
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

// EncryptionKey returns the primary key used for encryption (the most recent one).
func (p *Argon2Provider) EncryptionKey(ctx context.Context) ([]byte, error) {
	if len(p.keyStore.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keyStore.keys[0], nil
}

// DecryptionKeys returns all available keys for decryption.
func (p *Argon2Provider) DecryptionKeys(ctx context.Context) ([][]byte, error) {
	if len(p.keyStore.keys) == 0 {
		return nil, ErrNoKey
	}

	return p.keyStore.keys, nil
}
