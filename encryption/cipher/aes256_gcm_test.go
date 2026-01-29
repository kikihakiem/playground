//go:build unit

package cipher_test

import (
	"crypto/aes"
	cryptocipher "crypto/cipher"
	"crypto/sha256"
	"testing"

	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
	"github.com/stretchr/testify/assert"
)

func TestAES256GCM(t *testing.T) {
	var (
		salt = []byte("IxZVjMFODIeBCscvZbMEcT2ZESgWEmW1")
		key1 = []byte("MFYuo94qPvLiGC15cn9IzFZ8z1IAB344")
		key2 = []byte("GgrHdjRRMUdJsZIoDYjBI79kxi2thh3F")
	)

	t.Run("truncated nonce", func(t *testing.T) {
		keyProvider, err := key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.AES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		truncatedNonce := make([]byte, 10)
		_, err = cipher.Decipher(truncatedNonce, nil)
		assert.ErrorContains(t, err, "truncated")
	})

	t.Run("key rotation", func(t *testing.T) {
		plainText := []byte("secret")

		// encrypt secret with the old key
		keys := [][]byte{key1}
		keyProvider1, err := key.PBKDF2Provider(keys, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		oldCipher := cipher.AES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce1, cipherText1, err := oldCipher.Cipher(plainText)
		assert.NoError(t, err)

		// rotate key
		keys = prepend(keys, key2)
		keyProvider2, err := key.PBKDF2Provider(keys, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		newCipher := cipher.AES256GCM(
			keyProvider2,
			initvector.Deterministic(sha256.New),
		)

		// encrypt the same secret with the new key. Expect the result will be different
		nonce2, cipherText2, err := newCipher.Cipher(plainText)
		assert.NoError(t, err)
		assert.NotEqual(t, nonce1, nonce2)
		assert.NotEqual(t, cipherText1, cipherText2)

		// try to decrypt the old encrypted secret. Expect successful decryption
		deciphered, err := newCipher.Decipher(nonce1, cipherText1)
		assert.NoError(t, err)
		assert.Equal(t, plainText, deciphered)
	})

	t.Run("decrypt with wrong key", func(t *testing.T) {
		plainText := []byte("secret")
		keyProvider1, err := key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		cipher1 := cipher.AES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce, cipherText, err := cipher1.Cipher(plainText)
		assert.NoError(t, err)

		// wrong key
		keyProvider2, err := key.PBKDF2Provider([][]byte{key2}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		cipherWithWrongKey := cipher.AES256GCM(
			keyProvider2,
			initvector.Deterministic(sha256.New),
		)
		_, err = cipherWithWrongKey.Decipher(nonce, cipherText)
		assert.ErrorContains(t, err, "failed")

		// tampered cipher text
		cipherText[13] = 65
		_, err = cipher1.Decipher(nonce, cipherText)
		assert.ErrorContains(t, err, "failed")
	})

	t.Run("standard tag and nonce size", func(t *testing.T) {
		keyProvider, err := key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.AES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		block, err := aes.NewCipher(key1)
		assert.NoError(t, err)

		aesgcm, err := cryptocipher.NewGCM(block)
		assert.NoError(t, err)

		assert.Equal(t, aesgcm.Overhead(), cipher.AuthTagSize())
		assert.Equal(t, aesgcm.NonceSize(), cipher.NonceSize())
	})

	t.Run("no key", func(t *testing.T) {
		keyProvider, err := key.PBKDF2Provider([][]byte{}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.AES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		_, _, err = cipher.Cipher([]byte("secret"))
		assert.ErrorIs(t, err, key.ErrNoKey)

		_, err = cipher.Decipher(make([]byte, 12), make([]byte, 16))
		assert.ErrorIs(t, err, key.ErrNoKey)
	})
}

// defined this function for clarity
func prepend[T any](slice []T, elems ...T) []T {
	return append(elems, slice...)
}
