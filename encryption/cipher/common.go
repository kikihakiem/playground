package cipher

import "errors"

var ErrTruncated = errors.New("truncated text")

type rotatingKeyProvider interface {
	EncryptionKey() []byte
	DecryptionKeys() [][]byte
}

type initVectorer interface {
	InitVector(key, param []byte, size int) ([]byte, error)
}
