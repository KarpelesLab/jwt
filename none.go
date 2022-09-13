package jwt

import (
	"crypto"
	"io"
)

type noneAlgo struct{}

func (n noneAlgo) String() string {
	return "none"
}

func (n noneAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	return nil, nil
}

func (n noneAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	// cannot "verify" a not signed jwt, this will ALWAYS return an error
	return ErrInvalidSignature
}

func (n noneAlgo) reg() Algo {
	RegisterAlgo(n)
	return n
}
