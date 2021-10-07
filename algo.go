package jwt

import (
	"crypto"
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
	Sign(buf []byte, priv crypto.PrivateKey) ([]byte, error)

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
	HS845 Algo = hmacAlgo(crypto.SHA512).reg()

	RS256 Algo = rsaAlgo(crypto.SHA256).reg()
	RS384 Algo = rsaAlgo(crypto.SHA384).reg()
	RS512 Algo = rsaAlgo(crypto.SHA512).reg()

	PS256 Algo = rsaPssAlgo(crypto.SHA256).reg()
	PS384 Algo = rsaPssAlgo(crypto.SHA384).reg()
	PS512 Algo = rsaPssAlgo(crypto.SHA512).reg()

	ES256 Algo = ecdsaAlgo(crypto.SHA256).reg()
	ES384 Algo = ecdsaAlgo(crypto.SHA384).reg()
	ES512 Algo = ecdsaAlgo(crypto.SHA512).reg()

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
