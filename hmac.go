package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"io"
)

// hmacAlgo implements the Algo interface for HMAC-based signing algorithms
// (HS224, HS256, HS384, HS512). The underlying value is the crypto.Hash
// that determines the hash function used.
type hmacAlgo crypto.Hash

// String returns the JWT algorithm name (e.g. "HS256") for this HMAC algorithm.
func (h hmacAlgo) String() string {
	switch crypto.Hash(h) {
	case crypto.SHA224:
		return "HS224"
	case crypto.SHA256:
		return "HS256"
	case crypto.SHA384:
		return "HS384"
	case crypto.SHA512:
		return "HS512"
	default:
		return ""
	}
}

// Hash returns the underlying crypto.Hash used by this HMAC algorithm.
func (h hmacAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

// Sign computes the HMAC signature. The private key must be a []byte.
func (h hmacAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.([]byte)
	if !ok {
		return nil, ErrInvalidSignKey
	}
	if !h.Hash().Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	mac := hmac.New(h.Hash().New, pk)
	mac.Write(buf)
	return mac.Sum(nil), nil
}

// Verify checks the HMAC signature using constant-time comparison.
// The public key must be a []byte (the same shared secret used for signing).
func (h hmacAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	pk, ok := pub.([]byte)
	if !ok {
		return ErrInvalidSignature
	}
	if !h.Hash().Available() {
		return fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	mac := hmac.New(h.Hash().New, pk)
	mac.Write(buf)
	if !hmac.Equal(sign, mac.Sum(nil)) {
		return ErrInvalidSignature
	}
	return nil
}

func (h hmacAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}
