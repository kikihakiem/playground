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
	encryptedText3 := []byte(`{"p":"lEMctSYVzhJvYJZKTzSsStfbqugE8VTtPj6wBw1x","h":{"iv":"E9qSpdOfUMtrveT/","at":"QaBeEg/rnKGEjzi1sciVoQ=="}}`)

	plainText4 := []byte("Jl. Setapak Gg. Buntu")
	encryptedText4 := []byte(`{"p":"HKq7TRehRUPPT9PGzYE1gYjeuqGE","h":{"iv":"Cd8BkTwsUs190Xq3","at":"xfapwm/78DuPefLSuWWYsA=="}}`)

	deterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, cipher.AES256GCMKeySize),
			initvector.Deterministic(sha256.New),
		),
		encoding.JSONBase64(base64.StdEncoding),
	)

	nonDeterministicEncryptor := encryption.New(
		cipher.AES256GCM(
			key.PBKDF2Provider([][]byte{key2}, salt, sha1.New, 32, key.PBKDF2Iterations(1<<16)),
			initvector.Random(),
		),
		encoding.JSONBase64(base64.StdEncoding),
	)

	t.Run("deterministic encrypt", func(t *testing.T) {
		encrypted, err := deterministicEncryptor.Encrypt(plainText3)
		assert.NoError(t, err)
		assert.JSONEq(t, string(encryptedText3), string(encrypted))
	})

	t.Run("deterministic decrypt", func(t *testing.T) {
		decrypted, err := deterministicEncryptor.Decrypt(encryptedText3)
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
		decrypted, err := nonDeterministicEncryptor.Decrypt(encryptedText4)
		assert.NoError(t, err)
		assert.Equal(t, plainText4, decrypted)
	})
}
