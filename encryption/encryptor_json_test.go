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

func TestEncryptorJSON(t *testing.T) {
	salt := []byte("IxZVjMFODIeBCscvZbMEcT2ZESgWEmW1")
	key1 := []byte("MFYuo94qPvLiGC15cn9IzFZ8z1IAB344")
	key2 := []byte("GgrHdjRRMUdJsZIoDYjBI79kxi2thh3F")

	plainText3 := []byte("predovic.eugena.dc@bobobox.com")
	plainText4 := []byte("Jl. Setapak Gg. Buntu")

	keyProvider1, err := key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize)
	if err != nil {
		t.Fatalf("failed to create key provider 1: %v", err)
	}

	deterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		),
		encoding.JSONBase64(base64.StdEncoding),
	)

	keyProvider2, err := key.PBKDF2Provider([][]byte{key2}, salt, sha1.New, 32, key.PBKDF2Iterations(key.MinPBKDF2Iterations))
	if err != nil {
		t.Fatalf("failed to create key provider 2: %v", err)
	}

	nonDeterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			keyProvider2,
			initvector.Random(),
		),
		encoding.JSONBase64(base64.StdEncoding),
	)

	t.Run("deterministic encrypt", func(t *testing.T) {
		encrypted1, err := deterministicEncryptor.Encrypt(plainText3)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output
		encrypted2, err := deterministicEncryptor.Encrypt(plainText3)
		assert.NoError(t, err)
		assert.JSONEq(t, string(encrypted1), string(encrypted2))

		// Should be able to decrypt
		decrypted, err := deterministicEncryptor.Decrypt(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, plainText3, decrypted)
	})

	t.Run("deterministic decrypt", func(t *testing.T) {
		encrypted, err := deterministicEncryptor.Encrypt(plainText3)
		assert.NoError(t, err)

		decrypted, err := deterministicEncryptor.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText3, decrypted)
	})

	t.Run("non-deterministic encrypt/decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(plainText4)
		assert.NoError(t, err)

		// we cannot expect the encrypted text is fixed, so we assert the decryption result instead
		decrypted, err := nonDeterministicEncryptor.Decrypt([]byte(encrypted))
		assert.NoError(t, err)
		assert.Equal(t, plainText4, decrypted)
	})

	t.Run("non-deterministic decrypt", func(t *testing.T) {
		encrypted, err := nonDeterministicEncryptor.Encrypt(plainText4)
		assert.NoError(t, err)

		decrypted, err := nonDeterministicEncryptor.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText4, decrypted)
	})
}
