//go:build unit

package cipher_test

import (
	"context"
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
		ctx  = context.Background()
	)

	t.Run("truncated nonce", func(t *testing.T) {
		keyProvider, err := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.NewAES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		truncatedNonce := make([]byte, 10)
		_, err = cipher.Decipher(ctx, truncatedNonce, nil, nil)
		assert.ErrorContains(t, err, "truncated")
	})

	t.Run("key rotation", func(t *testing.T) {
		plainText := []byte("secret")

		// encrypt secret with the old key
		keys := [][]byte{key1}
		keyProvider1, err := key.NewPBKDF2Provider(keys, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		oldCipher := cipher.NewAES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce1, cipherText1, err := oldCipher.Cipher(ctx, plainText, nil)
		assert.NoError(t, err)

		// rotate key
		keys = prepend(keys, key2)
		keyProvider2, err := key.NewPBKDF2Provider(keys, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		newCipher := cipher.NewAES256GCM(
			keyProvider2,
			initvector.Deterministic(sha256.New),
		)

		// encrypt the same secret with the new key. Expect the result will be different
		nonce2, cipherText2, err := newCipher.Cipher(ctx, plainText, nil)
		assert.NoError(t, err)
		assert.NotEqual(t, nonce1, nonce2)
		assert.NotEqual(t, cipherText1, cipherText2)

		// try to decrypt the old encrypted secret. Expect successful decryption
		deciphered, err := newCipher.Decipher(ctx, nonce1, cipherText1, nil)
		assert.NoError(t, err)
		assert.Equal(t, plainText, deciphered)
	})

	t.Run("decrypt with wrong key", func(t *testing.T) {
		plainText := []byte("secret")
		keyProvider1, err := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		cipher1 := cipher.NewAES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce, cipherText, err := cipher1.Cipher(ctx, plainText, nil)
		assert.NoError(t, err)

		// wrong key
		keyProvider2, err := key.NewPBKDF2Provider([][]byte{key2}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		cipherWithWrongKey := cipher.NewAES256GCM(
			keyProvider2,
			initvector.Deterministic(sha256.New),
		)
		_, err = cipherWithWrongKey.Decipher(ctx, nonce, cipherText, nil)
		assert.ErrorContains(t, err, "failed")

		// tampered cipher text
		cipherText[13] = 65
		_, err = cipher1.Decipher(ctx, nonce, cipherText, nil)
		assert.ErrorContains(t, err, "failed")
	})

	t.Run("standard tag and nonce size", func(t *testing.T) {
		keyProvider, err := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.NewAES256GCM(
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
		keyProvider, err := key.NewPBKDF2Provider([][]byte{}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.NewAES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		_, _, err = cipher.Cipher(ctx, []byte("secret"), nil)
		assert.ErrorIs(t, err, key.ErrNoKey)

		_, err = cipher.Decipher(ctx, make([]byte, 12), make([]byte, 16), nil)
		assert.ErrorIs(t, err, key.ErrNoKey)
	})

	t.Run("AAD support", func(t *testing.T) {
		aad := []byte("additional-authenticated-data")
		plainText := []byte("sensitive-data")

		keyProvider, err := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		aesCipher := cipher.NewAES256GCM(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		t.Run("encrypt and decrypt with AAD", func(t *testing.T) {
			nonce, cipherText, err := aesCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)
			assert.NotEmpty(t, cipherText)

			decrypted, err := aesCipher.Decipher(ctx, nonce, cipherText, aad)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("decrypt fails with wrong AAD", func(t *testing.T) {
			nonce, cipherText, err := aesCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)

			wrongAAD := []byte("wrong-aad")
			_, err = aesCipher.Decipher(ctx, nonce, cipherText, wrongAAD)
			assert.Error(t, err)
		})

		t.Run("decrypt fails with nil AAD when encrypted with AAD", func(t *testing.T) {
			nonce, cipherText, err := aesCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)

			_, err = aesCipher.Decipher(ctx, nonce, cipherText, nil)
			assert.Error(t, err)
		})

		t.Run("different AAD produces different ciphertext", func(t *testing.T) {
			aad1 := []byte("aad-1")
			aad2 := []byte("aad-2")

			_, cipherText1, err := aesCipher.Cipher(ctx, plainText, aad1)
			assert.NoError(t, err)

			_, cipherText2, err := aesCipher.Cipher(ctx, plainText, aad2)
			assert.NoError(t, err)

			assert.NotEqual(t, cipherText1, cipherText2)
		})

		t.Run("long AAD", func(t *testing.T) {
			longAAD := make([]byte, 1024)
			for i := range longAAD {
				longAAD[i] = byte(i % 256)
			}

			nonce, cipherText, err := aesCipher.Cipher(ctx, plainText, longAAD)
			assert.NoError(t, err)

			decrypted, err := aesCipher.Decipher(ctx, nonce, cipherText, longAAD)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})
	})
}

// defined this function for clarity
func prepend[T any](slice []T, elems ...T) []T {
	return append(elems, slice...)
}
