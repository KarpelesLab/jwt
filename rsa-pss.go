package jwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
)

// rsaPssAlgo implements the Algo interface for RSA-PSS signing algorithms
// (PS256, PS384, PS512). The underlying value is the crypto.Hash used.
type rsaPssAlgo crypto.Hash

// String returns the JWT algorithm name (e.g. "PS256") for this RSA-PSS algorithm.
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

// Hash returns the underlying crypto.Hash used by this RSA-PSS algorithm.
func (h rsaPssAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

// Sign creates an RSA-PSS signature. The private key must implement
// crypto.Signer with an *rsa.PublicKey.
func (h rsaPssAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
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

	return pk.Sign(rand, hash.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h.Hash()})
}

// Verify checks an RSA-PSS signature against the given public key.
// If pub implements Public() crypto.PublicKey (e.g. *JWK), it will be unwrapped.
func (h rsaPssAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	if obj, ok := pub.(interface{ Public() crypto.PublicKey }); ok {
		pub = obj.Public()
	}

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
