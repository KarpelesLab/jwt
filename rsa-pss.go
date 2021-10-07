package jwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

type rsaPssAlgo crypto.Hash

func (h rsaPssAlgo) String() string {
	switch h.Hash() {
	case crypto.SHA224:
		return "PS224"
	case crypto.SHA256:
		return "PS256"
	case crypto.SHA384:
		return "PS384"
	case crypto.SHA512:
		return "PS512"
	default:
		return ""
	}
}

func (h rsaPssAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

func (h rsaPssAlgo) Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// ensure public key is a *rsa.PublicKey
	if _, ok := pk.Public().(*rsa.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}
	if !h.Hash().Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return pk.Sign(nil, hash.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h.Hash()})
}

func (h rsaPssAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidSignature
	}
	if !h.Hash().Available() {
		return fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return rsa.VerifyPSS(pk, h.Hash(), hash.Sum(nil), sign, nil) // The opts argument may be nil, in which case sensible defaults are used
}

func (h rsaPssAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}
