package cipher

// RotatingKeyProvider defines an interface for providing encryption and decryption keys.
// It supports key rotation by allowing multiple decryption keys.
type RotatingKeyProvider interface {
	EncryptionKey() ([]byte, error)
	DecryptionKeys() ([][]byte, error)
}

// InitVectorer defines an interface for generating initialization vectors (IV).
type InitVectorer interface {
	InitVector(key, param []byte, size int) ([]byte, error)
}
