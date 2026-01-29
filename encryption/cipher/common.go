package cipher

import "context"

// RotatingKeyProvider defines an interface for providing encryption and decryption keys.
// It supports key rotation by allowing multiple decryption keys.
type RotatingKeyProvider interface {
	EncryptionKey(ctx context.Context) ([]byte, error)
	DecryptionKeys(ctx context.Context) ([][]byte, error)
}

// InitVectorer defines an interface for generating initialization vectors (IV).
type InitVectorer interface {
	InitVector(ctx context.Context, key, param []byte, size int) ([]byte, error)
}
