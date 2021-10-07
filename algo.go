package jwt

import (
	"crypto"
	_ "crypto/sha256"
)

type Algo string

const (
	HS256 Algo = "HS256"
	RS256 Algo = "RS256"
	ES256 Algo = "ES256"
	EdDSA Algo = "EdDSA"
)

func (a Algo) IsValid() bool {
	switch a {
	case HS256, RS256, ES256, EdDSA:
		return true
	default:
		return false
	}
}

func (a Algo) Hash() crypto.Hash {
	switch a {
	case HS256, RS256, ES256:
		return crypto.SHA256
	case EdDSA:
		return crypto.Hash(0)
	default:
		return crypto.Hash(0)
	}
}

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
		return Algo("")
	}
}
