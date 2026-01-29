package cipher

type rotatingKeyProvider interface {
	EncryptionKey() ([]byte, error)
	DecryptionKeys() ([][]byte, error)
}

type initVectorer interface {
	InitVector(key, param []byte, size int) ([]byte, error)
}
