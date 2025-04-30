package encryption

import (
	"crypto/hmac"
	"crypto/rand"
	"hash"
)

type RandomIV struct{}

func NewRandomIVGenerator() *RandomIV {
	return &RandomIV{}
}

func (r *RandomIV) InitVector(_, _ []byte, size int) ([]byte, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

type DeterministicIV struct {
	HashFunc func() hash.Hash
}

func NewDeterministicIVGenerator(hashFunc func() hash.Hash) *DeterministicIV {
	return &DeterministicIV{hashFunc}
}

func (d *DeterministicIV) InitVector(key, param []byte, size int) ([]byte, error) {
	h := hmac.New(d.HashFunc, key)
	h.Write(param)
	return h.Sum(nil)[:size], nil
}
