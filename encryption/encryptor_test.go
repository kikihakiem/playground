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
	encryptedText1 := []byte("/reSGhsM//F08/shs6lWNlhJbaiFlVdyfp/IM8uayQ/l3Wl+xeG/NNScfmWBCLXfGrzANfYfeFiJsHSu28c5")

	key2 := []byte("GgrHdjRRMUdJsZIoDYjBI79kxi2thh3F")
	plainText2 := []byte("+855 126.007.4107")
	encryptedText2 := []byte("hVf4JU3F8QRq3HzWlY0iLYFO/t+hN6MDa0pH0ZJ1O7h4xzRk8TEQztN1GR5s")

	deterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize),
			initvector.Deterministic(sha256.New),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	nonDeterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			key.PBKDF2Provider([][]byte{key2}, salt, sha1.New, 32, key.PBKDF2Iterations(1<<16)),
			initvector.Random(),
		),
		encoding.SimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encrypt", func(t *testing.T) {
		encrypted, err := deterministicEncryptor.Encrypt(plainText1)
		assert.NoError(t, err)
		assert.Equal(t, encryptedText1, encrypted)
	})

	t.Run("deterministic decrypt", func(t *testing.T) {
		decrypted, err := deterministicEncryptor.Decrypt(encryptedText1)
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
		decrypted, err := nonDeterministicEncryptor.Decrypt(encryptedText2)
		assert.NoError(t, err)
		assert.Equal(t, plainText2, decrypted)
	})

	t.Run("cipher fails", func(t *testing.T) {
		invalidCipher := encryption.New(
			cipher.AES256GCM(
				key.PBKDF2Provider([][]byte{}, salt, sha256.New, 32), // empty key will fail
				initvector.Deterministic(sha256.New),
			),
			encoding.SimpleBase64(base64.RawStdEncoding),
		)

		_, err := invalidCipher.Encrypt(plainText1)
		assert.ErrorContains(t, err, "cipher")
	})

	t.Run("decipher fails", func(t *testing.T) {
		// Tamper with the encrypted text
		tamperedText := make([]byte, len(encryptedText1))
		copy(tamperedText, encryptedText1)
		tamperedText[len(tamperedText)-1] = 'X'

		_, err := deterministicEncryptor.Decrypt(tamperedText)
		assert.ErrorContains(t, err, "decipher")
	})

	t.Run("deserialize fails with invalid base64", func(t *testing.T) {
		invalidBase64 := []byte("!@#$%^&*") // Invalid base64 data

		_, err := deterministicEncryptor.Decrypt(invalidBase64)
		assert.ErrorContains(t, err, "deserialize")
	})
}
