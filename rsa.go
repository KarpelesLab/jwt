package jwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
)

type rsaAlgo crypto.Hash

func (h rsaAlgo) String() string {
	switch h.Hash() {
	case crypto.SHA224:
		return "RS224"
	case crypto.SHA256:
		return "RS256"
	case crypto.SHA384:
		return "RS384"
	case crypto.SHA512:
		return "RS512"
	default:
		return ""
	}
}

func (h rsaAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

func (h rsaAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}
	if !h.Hash().Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	// ensure public key is a *rsa.PublicKey
	if _, ok := pk.Public().(*rsa.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return pk.Sign(rand, hash.Sum(nil), h.Hash())
}

func (h rsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidSignature
	}
	if !h.Hash().Available() {
		return fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return rsa.VerifyPKCS1v15(pk, h.Hash(), hash.Sum(nil), sign)
}

func (h rsaAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}
