package key

import "crypto/subtle"

// keyStore holds the derived keys and provides zeroization functionality.
// It is embedded in all key provider types to share common key management.
type keyStore struct {
	keys [][]byte
}

// Zeroize clears all sensitive data from memory by overwriting keys with zeros.
// This should be called when the provider is no longer needed to prevent
// sensitive key material from remaining in memory.
func (ks *keyStore) Zeroize() {
	for i := range ks.keys {
		for j := range ks.keys[i] {
			ks.keys[i][j] = 0
		}
	}
	ks.keys = nil
}

// CompareKeys performs a constant-time comparison of two keys.
// Returns true if the keys are equal, false otherwise.
// This prevents timing attacks that could reveal information about key values.
func CompareKeys(key1, key2 []byte) bool {
	return subtle.ConstantTimeCompare(key1, key2) == 1
}
