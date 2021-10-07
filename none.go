package jwt

import "crypto"

type noneAlgo struct{}

func (n noneAlgo) String() string {
	return "none"
}

func (n noneAlgo) Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error) {
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
