package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
)

type ecdsaAlgo crypto.Hash

func (h ecdsaAlgo) String() string {
	switch h.Hash() {
	case crypto.SHA224:
		return "ES224"
	case crypto.SHA256:
		return "ES256"
	case crypto.SHA384:
		return "ES384"
	case crypto.SHA512:
		return "ES512"
	default:
		return ""
	}
}

func (h ecdsaAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

func (h ecdsaAlgo) Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// ensure public key is a *rsa.PublicKey
	if _, ok := pk.Public().(*ecdsa.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}
	if !h.Hash().Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return pk.Sign(nil, hash.Sum(nil), h.Hash())
}

func (h ecdsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidSignature
	}
	if !h.Hash().Available() {
		return fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	if !ecdsa.VerifyASN1(pk, hash.Sum(nil), sign) {
		return ErrInvalidSignature
	}

	return nil
}

func (h ecdsaAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}
