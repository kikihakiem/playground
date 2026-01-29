//go:build unit

package encryption_test

import (
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
		encrypted1, err := deterministicEncryptor.Encrypt(plainText1)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		encrypted2, err := deterministicEncryptor.Encrypt(plainText1)
		assert.NoError(t, err)
		assert.Equal(t, encrypted1, encrypted2)

		// Should be able to decrypt
		decrypted, err := deterministicEncryptor.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, plainText1, decrypted)
	})

	t.Run("deterministic decrypt", func(t *testing.T) {
		encrypted, err := deterministicEncryptor.Encrypt(plainText1)
		assert.NoError(t, err)

		decrypted, err := deterministicEncryptor.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText1, decrypted)
	})

	t.Run("non-deterministic encrypt/decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(plainText2)
		assert.NoError(t, err)

		// we cannot expect the encrypted text is fixed, so we assert the decryption result instead
		decrypted, err := nonDeterministicEncryptor.Decrypt([]byte(encrypted))
		assert.NoError(t, err)
		assert.Equal(t, plainText2, decrypted)
	})

	t.Run("non-deterministic decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(plainText2)
		assert.NoError(t, err)

		decrypted, err := nonDeterministicEncryptor.Decrypt(encrypted)
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

		_, err = invalidCipher.Encrypt(plainText1)
		assert.ErrorContains(t, err, "cipher")
	})

	t.Run("decipher fails", func(t *testing.T) {
		// Encrypt first
		encrypted, err := deterministicEncryptor.Encrypt(plainText1)
		assert.NoError(t, err)

		// Tamper with the encrypted text
		tamperedText := make([]byte, len(encrypted))
		copy(tamperedText, encrypted)
		tamperedText[len(tamperedText)-1] = 'X'

		_, err = deterministicEncryptor.Decrypt(tamperedText)
		assert.ErrorContains(t, err, "decipher")
	})

	t.Run("deserialize fails with invalid base64", func(t *testing.T) {
		invalidBase64 := []byte("!@#$%^&*") // Invalid base64 data

		_, err := deterministicEncryptor.Decrypt(invalidBase64)
		assert.ErrorContains(t, err, "deserialize")
	})
}
