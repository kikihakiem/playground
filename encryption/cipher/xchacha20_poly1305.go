package cipher

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// NewXChaCha20Poly1305 creates a new XChaCha20-Poly1305 cipher with the provided key provider and IV generator.
// XChaCha20-Poly1305 uses an extended 24-byte nonce, allowing for random nonces to be used safely.
func NewXChaCha20Poly1305(keyProvider RotatingKeyProvider, ivGenerator InitVectorer) *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		RotatingKeyProvider: keyProvider,
		InitVectorer:        ivGenerator,
		authTagSize:         chacha20poly1305.Overhead,
		nonceSize:           chacha20poly1305.NonceSizeX,
		cipher:              chacha20poly1305.NewX,
	}
}
