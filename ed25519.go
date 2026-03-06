package jwt

import (
	"crypto"
	"crypto/ed25519"
	"io"
)

// ed25519Algo implements the Algo interface for the EdDSA signing algorithm
// using Ed25519 keys.
type ed25519Algo struct{}

// String returns "EdDSA", the JWT algorithm name for Ed25519.
func (h ed25519Algo) String() string {
	return "EdDSA"
}

// Aliases returns alternate names for this algorithm ("EdDSA", "EDDSA").
func (h ed25519Algo) Aliases() []string {
	return []string{"EdDSA", "EDDSA"}
}

// Hash returns crypto.Hash(0) since Ed25519 performs its own hashing.
func (h ed25519Algo) Hash() crypto.Hash {
	return crypto.Hash(0)
}

// Sign creates an Ed25519 signature. The private key must implement
// crypto.Signer with an ed25519.PublicKey.
func (h ed25519Algo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// ensure public key is a ed25519.PublicKey
	if _, ok := pk.Public().(ed25519.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}

	return pk.Sign(rand, buf, h.Hash())
}

// Verify checks an Ed25519 signature against the given public key.
// If pub implements Public() crypto.PublicKey (e.g. *JWK), it will be unwrapped.
func (h ed25519Algo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	if obj, ok := pub.(interface{ Public() crypto.PublicKey }); ok {
		pub = obj.Public()
	}

	pk, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ErrInvalidSignature
	}

	if !ed25519.Verify(pk, buf, sign) {
		return ErrInvalidSignature
	}

	return nil
}

func (h ed25519Algo) reg() Algo {
	RegisterAlgo(h)
	return h
}
