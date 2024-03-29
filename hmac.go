package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"io"
)

type hmacAlgo crypto.Hash

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

func (h hmacAlgo) Hash() crypto.Hash {
	return crypto.Hash(h)
}

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
