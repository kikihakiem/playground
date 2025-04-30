package encryption_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/stretchr/testify/assert"
)

var (
	chachaSalt      = []byte("ChaCha20Poly1305TestSalt12345")
	chachaKey1      = []byte("ChaCha20Poly1305TestKey123456789012")
	chachaPlainText = []byte("Hello ChaCha20-Poly1305!")
)

var deterministicChaCha = encryption.NewEncryptor(
	encryption.NewChaCha20Poly1305Cipher(
		encryption.NewPBKDF2KeyProvider(
			[][]byte{chachaKey1},
			chachaSalt,
			sha256.New,
			encryption.PBKDF2KeySize(encryption.ChaCha20Poly1305KeySize),
		),
		encryption.NewDeterministicIVGenerator(sha256.New),
	),
	encryption.NewSimpleBase64Encoder(base64.RawStdEncoding),
)

var nonDeterministicChaCha = encryption.NewEncryptor(
	encryption.NewChaCha20Poly1305Cipher(
		encryption.NewPBKDF2KeyProvider(
			[][]byte{chachaKey1},
			chachaSalt,
			sha256.New,
			encryption.PBKDF2KeySize(encryption.ChaCha20Poly1305KeySize),
		),
		encryption.NewRandomIVGenerator(),
	),
	encryption.NewSimpleBase64Encoder(base64.RawStdEncoding),
)

func TestChaCha20Poly1305DeterministicEncryptDecrypt(t *testing.T) {
	encrypted1, err := deterministicChaCha.Encrypt(chachaPlainText)
	assert.NoError(t, err)

	encrypted2, err := deterministicChaCha.Encrypt(chachaPlainText)
	assert.NoError(t, err)

	// Deterministic encryption should produce same output for same input
	assert.Equal(t, encrypted1, encrypted2)

	// Test decryption
	decrypted, err := deterministicChaCha.Decrypt(encrypted1)
	assert.NoError(t, err)
	assert.Equal(t, chachaPlainText, decrypted)
}

func TestChaCha20Poly1305NonDeterministicEncryptDecrypt(t *testing.T) {
	encrypted1, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
	assert.NoError(t, err)

	encrypted2, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
	assert.NoError(t, err)

	// Non-deterministic encryption should produce different output for same input
	assert.NotEqual(t, encrypted1, encrypted2)

	// Test both encryptions can be decrypted correctly
	decrypted1, err := nonDeterministicChaCha.Decrypt(encrypted1)
	assert.NoError(t, err)
	assert.Equal(t, chachaPlainText, decrypted1)

	decrypted2, err := nonDeterministicChaCha.Decrypt(encrypted2)
	assert.NoError(t, err)
	assert.Equal(t, chachaPlainText, decrypted2)
}

func TestChaCha20Poly1305InvalidNonce(t *testing.T) {
	encrypted, err := nonDeterministicChaCha.Encrypt(chachaPlainText)
	assert.NoError(t, err)

	// Corrupt the nonce portion
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[0] = ^corrupted[0]

	_, err = nonDeterministicChaCha.Decrypt(corrupted)
	assert.Error(t, err)
}
