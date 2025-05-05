//go:build unit

package encryption_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/bobobox-id/go-library/encryption"
	"github.com/bobobox-id/go-library/encryption/initvector"
	"github.com/bobobox-id/go-library/encryption/key"
	"github.com/stretchr/testify/assert"
)

var (
	plainText3     = []byte("predovic.eugena.dc@bobobox.com")
	encryptedText3 = []byte(`{"p":"lEMctSYVzhJvYJZKTzSsStfbqugE8VTtPj6wBw1x","h":{"iv":"E9qSpdOfUMtrveT/","at":"QaBeEg/rnKGEjzi1sciVoQ=="}}`)

	plainText4     = []byte("Jl. Setapak Gg. Buntu")
	encryptedText4 = []byte(`{"p":"HKq7TRehRUPPT9PGzYE1gYjeuqGE","h":{"iv":"Cd8BkTwsUs190Xq3","at":"xfapwm/78DuPefLSuWWYsA=="}}`)
)

var deterministicEncryptor2 = encryption.New(
	encryption.CipherAES256GCM(
		key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, key.PBKDF2KeySize(encryption.AES256GCMKeySize)),
		initvector.Deterministic(sha256.New),
	),
	encryption.EncoderBase64JSON(base64.StdEncoding),
)

var nonDeterministicEncryptor2 = encryption.New(
	encryption.CipherAES256GCM(
		key.PBKDF2Provider([][]byte{key2}, salt, sha1.New, key.PBKDF2Iterations(1<<16)),
		initvector.Random(),
	),
	encryption.EncoderBase64JSON(base64.StdEncoding),
)

func TestDeterministicEncrypt2(t *testing.T) {
	encrypted, err := deterministicEncryptor2.Encrypt(plainText3)
	assert.NoError(t, err)
	assert.JSONEq(t, string(encryptedText3), string(encrypted))
}

func TestDeterministicDecrypt2(t *testing.T) {
	decrypted, err := deterministicEncryptor2.Decrypt(encryptedText3)
	assert.NoError(t, err)
	assert.Equal(t, plainText3, decrypted)
}

func TestNonDeterministicEncryptDecrypt2(t *testing.T) {
	encrypted, err := nonDeterministicEncryptor2.Encrypt(plainText4)
	assert.NoError(t, err)

	// we cannot expect the encrypted text is fixed, so we assert the decryption result instead
	decrypted, err := nonDeterministicEncryptor2.Decrypt([]byte(encrypted))
	assert.NoError(t, err)
	assert.Equal(t, plainText4, decrypted)
}

func TestNonDeterministicDecrypt2(t *testing.T) {
	decrypted, err := nonDeterministicEncryptor2.Decrypt(encryptedText4)
	assert.NoError(t, err)
	assert.Equal(t, plainText4, decrypted)
}
