package jwt

import (
	"crypto"
	"crypto/ed25519"
	"io"
)

type ed25519Algo struct{}

func (h ed25519Algo) String() string {
	return "EdDSA"
}

func (h ed25519Algo) Aliases() []string {
	return []string{"EdDSA", "EDDSA"}
}

func (h ed25519Algo) Hash() crypto.Hash {
	return crypto.Hash(0)
}

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

func (h ed25519Algo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
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
