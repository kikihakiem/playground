package initvector_test

import (
	"crypto/sha256"
	"testing"

	"github.com/bobobox-id/go-library/encryption/initvector"
	"github.com/stretchr/testify/assert"
)

func TestRandomInitVector(t *testing.T) {
	random := initvector.Random()

	// Test generating vectors of different sizes
	sizes := []int{12, 16, 24, 32}
	for _, size := range sizes {
		iv1, err := random.InitVector(nil, nil, size)
		assert.NoError(t, err)
		assert.Len(t, iv1, size)

		// Generate another IV of same size
		iv2, err := random.InitVector(nil, nil, size)
		assert.NoError(t, err)
		assert.Len(t, iv2, size)

		// Random IVs should be different
		assert.NotEqual(t, iv1, iv2)
	}
}

func TestDeterministicInitVector(t *testing.T) {
	deterministic := initvector.Deterministic(sha256.New)

	key := []byte("test-key")
	param := []byte("test-param")
	size := 16

	// Same inputs should produce same IV
	iv1, err := deterministic.InitVector(key, param, size)
	assert.NoError(t, err)
	assert.Len(t, iv1, size)

	iv2, err := deterministic.InitVector(key, param, size)
	assert.NoError(t, err)
	assert.Len(t, iv2, size)

	assert.Equal(t, iv1, iv2)

	// Different params should produce different IVs
	iv3, err := deterministic.InitVector(key, []byte("different-param"), size)
	assert.NoError(t, err)
	assert.NotEqual(t, iv1, iv3)

	// Different keys should produce different IVs
	iv4, err := deterministic.InitVector([]byte("different-key"), param, size)
	assert.NoError(t, err)
	assert.NotEqual(t, iv1, iv4)
}
