package jwt

import (
	"crypto"
	"fmt"
	"io"

	"github.com/KarpelesLab/mldsa"
)

// mldsaAlgo implements the Algo interface for ML-DSA (Module-Lattice Digital
// Signature Algorithm) as specified in FIPS 204. ML-DSA is a post-quantum
// signature scheme.
type mldsaAlgo struct {
	name  string
	level int // 44, 65, or 87
}

var (
	MLDSA44 Algo = mldsaAlgo{name: "ML-DSA-44", level: 44}.reg()
	MLDSA65 Algo = mldsaAlgo{name: "ML-DSA-65", level: 65}.reg()
	MLDSA87 Algo = mldsaAlgo{name: "ML-DSA-87", level: 87}.reg()
)

// String returns the algorithm name (e.g. "ML-DSA-65").
func (a mldsaAlgo) String() string {
	return a.name
}

// Sign creates an ML-DSA signature over the raw message. The private key must
// implement crypto.Signer with the corresponding ML-DSA public key type.
func (a mldsaAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// Validate that the key matches the expected level
	switch a.level {
	case 44:
		if _, ok := pk.Public().(*mldsa.PublicKey44); !ok {
			return nil, ErrInvalidSignKey
		}
	case 65:
		if _, ok := pk.Public().(*mldsa.PublicKey65); !ok {
			return nil, ErrInvalidSignKey
		}
	case 87:
		if _, ok := pk.Public().(*mldsa.PublicKey87); !ok {
			return nil, ErrInvalidSignKey
		}
	}

	return pk.Sign(rand, buf, crypto.Hash(0))
}

// Verify verifies an ML-DSA signature. If pub implements
// Public() crypto.PublicKey (e.g. *JWK), it will be unwrapped.
func (a mldsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	if obj, ok := pub.(interface{ Public() crypto.PublicKey }); ok {
		pub = obj.Public()
	}

	switch a.level {
	case 44:
		pk, ok := pub.(*mldsa.PublicKey44)
		if !ok {
			return fmt.Errorf("%w: expected *mldsa.PublicKey44, got %T", ErrInvalidPublicKey, pub)
		}
		if !pk.Verify(sign, buf, nil) {
			return ErrInvalidSignature
		}
	case 65:
		pk, ok := pub.(*mldsa.PublicKey65)
		if !ok {
			return fmt.Errorf("%w: expected *mldsa.PublicKey65, got %T", ErrInvalidPublicKey, pub)
		}
		if !pk.Verify(sign, buf, nil) {
			return ErrInvalidSignature
		}
	case 87:
		pk, ok := pub.(*mldsa.PublicKey87)
		if !ok {
			return fmt.Errorf("%w: expected *mldsa.PublicKey87, got %T", ErrInvalidPublicKey, pub)
		}
		if !pk.Verify(sign, buf, nil) {
			return ErrInvalidSignature
		}
	}

	return nil
}

func (a mldsaAlgo) reg() Algo {
	RegisterAlgo(a)
	return a
}
