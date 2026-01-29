package encryption

import "errors"

// ErrTruncated is returned when the encrypted data is too short to contain
// the required components (nonce, ciphertext, and authentication tag).
var ErrTruncated = errors.New("truncated encrypted data")
