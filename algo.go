package jwt

import (
	"crypto"
	_ "crypto/sha256"
)

type Algo interface {
	String() string
	Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error)
	Verify(buf, sign []byte, pub crypto.PublicKey) error // should return ErrInvalidSignature if invalid, or any other error
}

var (
	HS256 Algo = hmacAlgo(crypto.SHA256)
	RS256 Algo = rsaAlgo(crypto.SHA256)
	ES256 Algo = ecdsaAlgo(crypto.SHA256)
	EdDSA Algo = &ed25519Algo{}
)

func parseAlgo(v string) Algo {
	switch v {
	case "HS256":
		return HS256
	case "RS256":
		return RS256
	case "ES256":
		return ES256
	case "EdDSA", "EDDSA": // sometimes stylized uppercase
		return EdDSA
	default:
		// unsupported
		return nil
	}
}
