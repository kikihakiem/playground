//go:build unit

package cipher_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/kikihakiem/playground/encryption"
	"github.com/kikihakiem/playground/encryption/cipher"
	"github.com/kikihakiem/playground/encryption/encoding"
	"github.com/kikihakiem/playground/encryption/initvector"
	"github.com/kikihakiem/playground/encryption/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChaCha20Poly1305(t *testing.T) {
	var (
		chachaSalt      = []byte("ChaCha20Poly1305TestSalt12345")
		chachaKey1      = []byte("ChaCha20Poly1305TestKey123456789012")
		chachaPlainText = []byte("Hello ChaCha20-Poly1305!")
		ctx             = context.Background()
	)

	keyProvider1, err := key.NewArgon2Provider(
		[][]byte{chachaKey1},
		chachaSalt,
		cipher.ChaCha20Poly1305KeySize,
	)
	if err != nil {
		t.Fatalf("failed to create key provider 1: %v", err)
	}

	deterministicChaCha := encryption.New(
		cipher.NewChaCha20Poly1305(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	keyProvider2, err := key.NewArgon2Provider(
		[][]byte{chachaKey1},
		chachaSalt,
		cipher.ChaCha20Poly1305KeySize,
	)
	if err != nil {
		t.Fatalf("failed to create key provider 2: %v", err)
	}

	nonDeterministicChaCha := encryption.New(
		cipher.NewChaCha20Poly1305(
			keyProvider2,
			initvector.Random(),
		),
		encoding.NewSimpleBase64(base64.RawStdEncoding),
	)

	t.Run("deterministic encryption", func(t *testing.T) {
		encrypted1, err := deterministicChaCha.Encrypt(ctx, chachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := deterministicChaCha.Encrypt(ctx, chachaPlainText)
		assert.NoError(t, err)

		// Deterministic encryption should produce same output for same input
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		decrypted, err := deterministicChaCha.Decrypt(ctx, encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted)
	})

	t.Run("non-deterministic encryption", func(t *testing.T) {
		encrypted1, err := nonDeterministicChaCha.Encrypt(ctx, chachaPlainText)
		assert.NoError(t, err)

		encrypted2, err := nonDeterministicChaCha.Encrypt(ctx, chachaPlainText)
		assert.NoError(t, err)

		// Non-deterministic encryption should produce different output for same input
		assert.NotEqual(t, encrypted1, encrypted2)

		// Test both encryptions can be decrypted correctly
		decrypted1, err := nonDeterministicChaCha.Decrypt(ctx, encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted1)

		decrypted2, err := nonDeterministicChaCha.Decrypt(ctx, encrypted2)
		assert.NoError(t, err)
		assert.Equal(t, chachaPlainText, decrypted2)
	})

	t.Run("invalid nonce", func(t *testing.T) {
		encrypted, err := nonDeterministicChaCha.Encrypt(ctx, chachaPlainText)
		assert.NoError(t, err)

		// Corrupt the nonce portion
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[0] = ^corrupted[0]

		_, err = nonDeterministicChaCha.Decrypt(ctx, corrupted)
		assert.Error(t, err)
	})

	t.Run("no key", func(t *testing.T) {
		keyProvider, err := key.NewPBKDF2Provider([][]byte{}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider: %v", err)
		}

		cipher := cipher.NewChaCha20Poly1305(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		_, _, err = cipher.Cipher(ctx, []byte("secret"), nil)
		assert.ErrorIs(t, err, key.ErrNoKey)

		_, err = cipher.Decipher(ctx, make([]byte, 12), make([]byte, 16), nil)
		assert.ErrorIs(t, err, key.ErrNoKey)
	})
	t.Run("decrypt with wrong key", func(t *testing.T) {
		plainText := []byte("secret")
		keyProvider1, err := key.NewPBKDF2Provider([][]byte{chachaKey1}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 1: %v", err)
		}

		cipher1 := cipher.NewChaCha20Poly1305(
			keyProvider1,
			initvector.Deterministic(sha256.New),
		)
		nonce, cipherText, err := cipher1.Cipher(ctx, plainText, nil)
		assert.NoError(t, err)

		// wrong key
		keyProvider2, err := key.NewPBKDF2Provider([][]byte{[]byte("wrong key")}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		if err != nil {
			t.Fatalf("failed to create key provider 2: %v", err)
		}

		cipherWithWrongKey := cipher.NewChaCha20Poly1305(
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

	t.Run("AAD support", func(t *testing.T) {
		aad := []byte("additional-authenticated-data")
		plainText := []byte("sensitive-data")

		keyProvider, err := key.NewPBKDF2Provider([][]byte{chachaKey1}, chachaSalt, sha256.New, cipher.ChaCha20Poly1305KeySize)
		require.NoError(t, err)

		chachaCipher := cipher.NewChaCha20Poly1305(
			keyProvider,
			initvector.Deterministic(sha256.New),
		)

		t.Run("encrypt and decrypt with AAD", func(t *testing.T) {
			nonce, cipherText, err := chachaCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)
			assert.NotEmpty(t, cipherText)

			decrypted, err := chachaCipher.Decipher(ctx, nonce, cipherText, aad)
			assert.NoError(t, err)
			assert.Equal(t, plainText, decrypted)
		})

		t.Run("decrypt fails with wrong AAD", func(t *testing.T) {
			nonce, cipherText, err := chachaCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)

			wrongAAD := []byte("wrong-aad")
			_, err = chachaCipher.Decipher(ctx, nonce, cipherText, wrongAAD)
			assert.Error(t, err)
		})

		t.Run("decrypt fails with nil AAD when encrypted with AAD", func(t *testing.T) {
			nonce, cipherText, err := chachaCipher.Cipher(ctx, plainText, aad)
			assert.NoError(t, err)

			_, err = chachaCipher.Decipher(ctx, nonce, cipherText, nil)
			assert.Error(t, err)
		})

		t.Run("different AAD produces different ciphertext", func(t *testing.T) {
			aad1 := []byte("aad-1")
			aad2 := []byte("aad-2")

			_, cipherText1, err := chachaCipher.Cipher(ctx, plainText, aad1)
			assert.NoError(t, err)

			_, cipherText2, err := chachaCipher.Cipher(ctx, plainText, aad2)
			assert.NoError(t, err)

			assert.NotEqual(t, cipherText1, cipherText2)
		})
	})
}
