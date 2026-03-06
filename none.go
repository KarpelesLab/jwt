package jwt

import (
	"crypto"
	"io"
)

// noneAlgo implements the Algo interface for the "none" algorithm, which
// produces no signature. Verification always fails since there is nothing
// to verify.
type noneAlgo struct{}

// String returns "none", the JWT algorithm name for unsigned tokens.
func (n noneAlgo) String() string {
	return "none"
}

// Sign returns nil for both the signature and error, producing an unsigned token.
func (n noneAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	return nil, nil
}

// Verify always returns ErrInvalidSignature since unsigned tokens cannot be verified.
func (n noneAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	// cannot "verify" a not signed jwt, this will ALWAYS return an error
	return ErrInvalidSignature
}

func (n noneAlgo) reg() Algo {
	RegisterAlgo(n)
	return n
}
