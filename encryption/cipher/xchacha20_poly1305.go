package cipher

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func XChaCha20Poly1305(keyProvider rotatingKeyProvider, ivGenerator initVectorer) *chaCha20Poly1305 {
	return &chaCha20Poly1305{
		rotatingKeyProvider: keyProvider,
		initVectorer:        ivGenerator,
		authTagSize:         chacha20poly1305.Overhead,
		nonceSize:           chacha20poly1305.NonceSizeX,
		cipher:              chacha20poly1305.NewX,
	}
}
