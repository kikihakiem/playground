//go:build unit

package encryption_test

import (
	"crypto/sha256"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/stretchr/testify/assert"
)

func newDeterministicCipher(keys [][]byte) *encryption.AES256GCM {
	return encryption.NewAES256GCMCipher(
		encryption.NewPBKDF2KeyProvider(keys, salt, sha256.New, encryption.PBKDF2KeySize(encryption.AES256GCMKeySize)),
		encryption.NewDeterministicIVGenerator(sha256.New),
	)
}

func newNonDeterministicCipher() *encryption.AES256GCM {
	return encryption.NewAES256GCMCipher(
		encryption.NewPBKDF2KeyProvider([][]byte{key2}, salt, sha256.New, encryption.PBKDF2KeySize(encryption.AES256GCMKeySize)),
		encryption.NewRandomIVGenerator(),
	)
}

func TestTruncatedNonce(t *testing.T) {
	cipher := newDeterministicCipher([][]byte{key1})

	truncatedNonce := make([]byte, 10)
	_, err := cipher.Decipher(truncatedNonce, nil)
	assert.ErrorContains(t, err, "truncated")
}

func TestKeyRotation(t *testing.T) {
	plainText := []byte("secret")

	// encrypt secret with the old key
	keys := [][]byte{key1}
	oldCipher := newDeterministicCipher(keys)
	nonce1, cipherText1, err := oldCipher.Cipher(plainText)
	assert.NoError(t, err)

	// rotate key
	keys = prepend(keys, key2)
	newCipher := newDeterministicCipher(keys)

	// encrypt the same secret with the new key. Expect the result will be different
	nonce2, cipherText2, err := newCipher.Cipher(plainText)
	assert.NoError(t, err)
	assert.NotEqual(t, nonce1, nonce2)
	assert.NotEqual(t, cipherText1, cipherText2)

	// try to decrypt the old encrypted secret. Expect successful decryption
	deciphered, err := newCipher.Decipher(nonce1, cipherText1)
	assert.NoError(t, err)
	assert.Equal(t, plainText, deciphered)
}

// defined this function for clarity
func prepend[T any](slice []T, elems ...T) []T {
	return append(elems, slice...)
}

func TestNegativeCases(t *testing.T) {
	plainText := []byte("secret")
	cipher := newDeterministicCipher([][]byte{key1})
	nonce, cipherText, err := cipher.Cipher(plainText)
	assert.NoError(t, err)

	// wrong key
	cipherWithWrongKey := newDeterministicCipher([][]byte{key2})
	_, err = cipherWithWrongKey.Decipher(nonce, cipherText)
	assert.ErrorContains(t, err, "failed")

	// tampered cipher text
	cipherText[13] = 65
	_, err = cipher.Decipher(nonce, cipherText)
	assert.ErrorContains(t, err, "failed")
}

func TestNonDeterministicity(t *testing.T) {
	cipher := newNonDeterministicCipher()
	plainText := []byte("secret")
	nonce1, cipherText1, err := cipher.Cipher(plainText)
	assert.NoError(t, err)

	nonce2, cipherText2, err := cipher.Cipher(plainText)
	assert.NoError(t, err)

	// expect different result
	assert.NotEqual(t, nonce1, nonce2)
	assert.NotEqual(t, cipherText1, cipherText2)
}
