package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
)

// Algo is a jwt signature algorithm. Typical values include HS256 and ES256.
// By implementing this interface, you can also add support for your own
// custom types. Remember to call RegisterAlgo() so your new algo can be
// recognized appropriately.
type Algo interface {
	// String should return the name of the algo, for example "HS256"
	String() string

	// Sign should sign the provided buffer, and return the resulting
	// signature. If the private key isn't of the appropriate type, an
	// error should be triggered.
	Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error)

	// Verify must verify the provided signature and return an error
	// if the public key is not of the appropriate type or the signature
	// is not valid.
	Verify(buf, sign []byte, pub crypto.PublicKey) error
}

// note: the .reg() just performs a call to RegisterAlgo() and returns the
// object itself.
var (
	// algos list is found in RFC7518:
	// https://datatracker.ietf.org/doc/html/rfc7518#section-3

	HS256 Algo = hmacAlgo(crypto.SHA256).reg()
	HS384 Algo = hmacAlgo(crypto.SHA384).reg()
	HS512 Algo = hmacAlgo(crypto.SHA512).reg()

	RS256 Algo = rsaAlgo(crypto.SHA256).reg()
	RS384 Algo = rsaAlgo(crypto.SHA384).reg()
	RS512 Algo = rsaAlgo(crypto.SHA512).reg()

	PS256 Algo = rsaPssAlgo(crypto.SHA256).reg()
	PS384 Algo = rsaPssAlgo(crypto.SHA384).reg()
	PS512 Algo = rsaPssAlgo(crypto.SHA512).reg()

	ES224  Algo = ecdsaAlgo(1).reg()
	ES256  Algo = ecdsaAlgo(2).reg()
	ES384  Algo = ecdsaAlgo(3).reg()
	ES512  Algo = ecdsaAlgo(4).reg()
	ES256K Algo = ecdsaAlgo(5).reg()

	EdDSA Algo = ed25519Algo{}.reg()
	None  Algo = noneAlgo{}.reg()

	algoMap = map[string]Algo{}
)

// RegisterAlgo allows registration of custom algorithms. We assume this will
// be called during init in a single thread, so no locking is performed.
func RegisterAlgo(obj Algo) {
	algoMap[obj.String()] = obj

	if al, ok := obj.(interface{ Aliases() []string }); ok {
		for _, v := range al.Aliases() {
			algoMap[v] = obj
		}
	}
}

func parseAlgo(v string) Algo {
	if a, ok := algoMap[v]; ok {
		return a
	}
	return nil
}

// GetAlgoForSigner will guess the correct algorithm for a given [crypto.PrivateKey]
func GetAlgoForSigner(s crypto.PrivateKey) (Algo, error) {
	if pub, ok := s.(interface{ Public() crypto.PublicKey }); ok {
		switch pubkey := pub.Public().(type) {
		case *ecdsa.PublicKey:
			switch pubkey.Curve.Params().Name {
			case "P-224":
				return ES224, nil
			case "P-256":
				return ES256, nil
			case "P-384":
				return ES384, nil
			case "P-521":
				return ES512, nil
			default:
				return nil, fmt.Errorf("no known jwt algorithm for ECDSA curve %s", pubkey.Curve.Params().Name)
			}
		case ed25519.PublicKey:
			return EdDSA, nil
		case *rsa.PublicKey:
			switch pubkey.Size() {
			case 32:
				return RS256, nil
			case 48:
				return RS384, nil
			case 64:
				return RS512, nil
			default:
				return nil, fmt.Errorf("unsupported RSA key size=%d", pubkey.Size())
			}
		default:
			return nil, fmt.Errorf("unsupported public key type %T", pubkey)
		}
	}
	return nil, fmt.Errorf("unsupported private key type %T", s)
}
