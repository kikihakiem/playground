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
	salt           = []byte("IxZVjMFODIeBCscvZbMEcT2ZESgWEmW1")
	key1           = []byte("MFYuo94qPvLiGC15cn9IzFZ8z1IAB344")
	plainText1     = []byte("christiansen_sen_russel@bobobox.com")
	encryptedText1 = []byte("/reSGhsM//F08/shs6lWNlhJbaiFlVdyfp/IM8uayQ/l3Wl+xeG/NNScfmWBCLXfGrzANfYfeFiJsHSu28c5")

	key2           = []byte("GgrHdjRRMUdJsZIoDYjBI79kxi2thh3F")
	plainText2     = []byte("+855 126.007.4107")
	encryptedText2 = []byte("hVf4JU3F8QRq3HzWlY0iLYFO/t+hN6MDa0pH0ZJ1O7h4xzRk8TEQztN1GR5s")
)

var deterministicEncryptor = encryption.New(
	encryption.CipherAES256GCM(
		key.PBKDF2Provider([][]byte{key1}, salt, sha256.New, key.PBKDF2KeySize(encryption.AES256GCMKeySize)),
		initvector.Deterministic(sha256.New),
	),
	encryption.EncoderBase64(base64.RawStdEncoding),
)

var nonDeterministicEncryptor = encryption.New(
	encryption.CipherAES256GCM(
		key.PBKDF2Provider([][]byte{key2}, salt, sha1.New, key.PBKDF2Iterations(1<<16)),
		initvector.Random(),
	),
	encryption.EncoderBase64(base64.RawStdEncoding),
)

func TestDeterministicEncrypt(t *testing.T) {
	encrypted, err := deterministicEncryptor.Encrypt(plainText1)
	assert.NoError(t, err)
	assert.Equal(t, encryptedText1, encrypted)
}

func TestDeterministicDecrypt(t *testing.T) {
	decrypted, err := deterministicEncryptor.Decrypt(encryptedText1)
	assert.NoError(t, err)
	assert.Equal(t, plainText1, decrypted)
}

func TestNonDeterministicEncryptDecrypt(t *testing.T) {
	encrypted, err := nonDeterministicEncryptor.Encrypt(plainText2)
	assert.NoError(t, err)

	// we cannot expect the encrypted text is fixed, so we assert the decryption result instead
	decrypted, err := nonDeterministicEncryptor.Decrypt([]byte(encrypted))
	assert.NoError(t, err)
	assert.Equal(t, plainText2, decrypted)
}

func TestNonDeterministicDecrypt(t *testing.T) {
	decrypted, err := nonDeterministicEncryptor.Decrypt(encryptedText2)
	assert.NoError(t, err)
	assert.Equal(t, plainText2, decrypted)
}
