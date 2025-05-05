package cipher

import "errors"

var ErrTruncated = errors.New("truncated text")

type rotatingKeyProvider interface {
	EncryptionKey() ([]byte, error)
	DecryptionKeys() ([][]byte, error)
}

type initVectorer interface {
	InitVector(key, param []byte, size int) ([]byte, error)
}
