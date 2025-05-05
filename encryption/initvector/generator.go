package initvector

import (
	"crypto/hmac"
	"crypto/rand"
	"hash"
)

type random struct{}

func Random() *random {
	return &random{}
}

func (r *random) InitVector(_, _ []byte, size int) ([]byte, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

type deterministic struct {
	HashFunc func() hash.Hash
}

func Deterministic(hashFunc func() hash.Hash) *deterministic {
	return &deterministic{hashFunc}
}

func (d *deterministic) InitVector(key, param []byte, size int) ([]byte, error) {
	h := hmac.New(d.HashFunc, key)
	h.Write(param)
	return h.Sum(nil)[:size], nil
}
