//go:build unit

package encryption_test

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption"
	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
	"github.com/stretchr/testify/assert"
)

func TestEncryptor(t *testing.T) {
	salt := []byte("IxZVjMFODIeBCscvZbMEcT2ZESgWEmW1")
	key1 := []byte("MFYuo94qPvLiGC15cn9IzFZ8z1IAB344")
	plainText1 := []byte("christiansen_sen_russel@bobobox.com")

	key2 := []byte("GgrHdjRRMUdJsZIoDYjBI79kxi2thh3F")
	plainText2 := []byte("+855 126.007.4107")

	ctx := context.Background()

	keyProvider1, err := key.NewPBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
	if err != nil {
		t.Fatalf("failed to create key provider 1: %v", err)
	}

	deterministicEncryptor := encryption.New(
		cipher.NewAES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	keyProvider2, err := key.NewPBKDF2Provider([][]byte{key2}, salt, sha1.New, 32, key.PBKDF2Iterations(key.MinPBKDF2Iterations))
	if err != nil {
		t.Fatalf("failed to create key provider 2: %v", err)
	}

	nonDeterministicEncryptor := encryption.New(
		cipher.NewAES256GCM(
			keyProvider2,
			initvector.Random(),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encrypt", func(t *testing.T) {
		encrypted1, err := deterministicEncryptor.Encrypt(ctx, plainText1)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		encrypted2, err := deterministicEncryptor.Encrypt(ctx, plainText1)
		assert.NoError(t, err)
		assert.Equal(t, encrypted1, encrypted2)

		// Should be able to decrypt
		decrypted, err := deterministicEncryptor.Decrypt(ctx, encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, plainText1, decrypted)
	})

	t.Run("deterministic decrypt", func(t *testing.T) {
		encrypted, err := deterministicEncryptor.Encrypt(ctx, plainText1)
		assert.NoError(t, err)

		decrypted, err := deterministicEncryptor.Decrypt(ctx, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText1, decrypted)
	})

	t.Run("non-deterministic encrypt/decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(ctx, plainText2)
		assert.NoError(t, err)

		// we cannot expect the encrypted text is fixed, so we assert the decryption result instead
		decrypted, err := nonDeterministicEncryptor.Decrypt(ctx, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText2, decrypted)
	})

	t.Run("non-deterministic decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(ctx, plainText2)
		assert.NoError(t, err)

		decrypted, err := nonDeterministicEncryptor.Decrypt(ctx, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText2, decrypted)
	})

	t.Run("cipher fails", func(t *testing.T) {
		// Empty key array is allowed but will fail when trying to encrypt
		emptyKeyProvider, err := key.NewPBKDF2Provider([][]byte{}, salt, sha256.New, 32)
		assert.NoError(t, err) // Provider creation succeeds

		invalidCipher := encryption.New(
			cipher.NewAES256GCM(
				emptyKeyProvider, // Empty keys will fail on encryption
				initvector.Deterministic(sha256.New),
			),
			encoding.NewSimpleBase64(base64.RawStdEncoding),
		)

		_, err = invalidCipher.Encrypt(ctx, plainText1)
		assert.ErrorContains(t, err, "cipher")
	})

	t.Run("decipher fails", func(t *testing.T) {
		// Encrypt first
		encrypted, err := deterministicEncryptor.Encrypt(ctx, plainText1)
		assert.NoError(t, err)

		// Tamper with the encrypted text
		tamperedText := make([]byte, len(encrypted))
		copy(tamperedText, encrypted)
		tamperedText[len(tamperedText)-1] = 'X'

		_, err = deterministicEncryptor.Decrypt(ctx, tamperedText)
		assert.ErrorContains(t, err, "decipher")
	})

	t.Run("deserialize fails with invalid base64", func(t *testing.T) {
		invalidBase64 := []byte("!@#$%^&*") // Invalid base64 data

		_, err := deterministicEncryptor.Decrypt(ctx, invalidBase64)
		assert.ErrorContains(t, err, "deserialize")
	})

	t.Run("AAD support", func(t *testing.T) {
		aad := []byte("additional-authenticated-data")
		plainText := []byte("sensitive-data-to-encrypt")

		t.Run("encrypt and decrypt with AAD", func(t *testing.T) {
			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)
			assert.NotEmpty(t, encrypted)

			decrypted, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted, aad)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("decrypt fails with wrong AAD", func(t *testing.T) {
			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)

			wrongAAD := []byte("wrong-aad")
			_, err = deterministicEncryptor.DecryptWithAAD(ctx, encrypted, wrongAAD)
			assert.ErrorContains(t, err, "decipher")
		})

		t.Run("decrypt fails with nil AAD when encrypted with AAD", func(t *testing.T) {
			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, aad)
			assert.NoError(t, err)

			// Try to decrypt without AAD (nil)
			_, err = deterministicEncryptor.DecryptWithAAD(ctx, encrypted, nil)
			assert.ErrorContains(t, err, "decipher")
		})

		t.Run("encrypt with nil AAD decrypts with nil AAD", func(t *testing.T) {
			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, nil)
			assert.NoError(t, err)

			decrypted, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted, nil)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("encrypt with empty AAD decrypts with empty AAD", func(t *testing.T) {
			emptyAAD := []byte{}
			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, emptyAAD)
			assert.NoError(t, err)

			decrypted, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted, emptyAAD)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("backward compatibility - Encrypt/Decrypt without AAD", func(t *testing.T) {
			// Old API should still work (uses nil AAD internally)
			encrypted, err := deterministicEncryptor.Encrypt(ctx, plainText)
			assert.NoError(t, err)

			decrypted, err := deterministicEncryptor.Decrypt(ctx, encrypted)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("different AAD produces different ciphertext", func(t *testing.T) {
			aad1 := []byte("aad-1")
			aad2 := []byte("aad-2")

			encrypted1, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, aad1)
			assert.NoError(t, err)

			encrypted2, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, aad2)
			assert.NoError(t, err)

			// Different AAD should produce different ciphertexts
			assert.NotEqual(t, encrypted1, encrypted2)

			// But both should decrypt correctly with their respective AAD
			decrypted1, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted1, aad1)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted1)

			decrypted2, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted2, aad2)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted2)
		})

		t.Run("long AAD", func(t *testing.T) {
			longAAD := make([]byte, 1024)
			for i := range longAAD {
				longAAD[i] = byte(i % 256)
			}

			encrypted, err := deterministicEncryptor.EncryptWithAAD(ctx, plainText, longAAD)
			assert.NoError(t, err)

			decrypted, err := deterministicEncryptor.DecryptWithAAD(ctx, encrypted, longAAD)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})
	})
}
