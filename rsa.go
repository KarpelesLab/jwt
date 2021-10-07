package jwt

import (
	"crypto"
	"crypto/rsa"
)

type rsaAlgo crypto.Hash

func (h rsaAlgo) String() string {
	switch h.Hash() {
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

func (h rsaAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

func (h rsaAlgo) Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// ensure public key is a *rsa.PublicKey
	if _, ok := pk.Public().(*rsa.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}

	hash := h.Hash().New()
	hash.Write(buf)

	return pk.Sign(nil, hash.Sum(nil), h.Hash())
}

func (h rsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidSignature
	}
	hash := h.Hash().New()
	hash.Write(buf)

	return rsa.VerifyPKCS1v15(pk, h.Hash(), hash.Sum(nil), sign)
}

func (h rsaAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}
