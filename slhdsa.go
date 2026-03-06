package jwt

import (
	"crypto"
	"fmt"
	"io"

	"github.com/KarpelesLab/slhdsa"
)

// slhdsaAlgo implements the Algo interface for SLH-DSA (Stateless Hash-Based
// Digital Signature Algorithm) as specified in FIPS 205. SLH-DSA is a
// post-quantum signature scheme based on hash functions.
type slhdsaAlgo struct {
	params *slhdsa.Params
}

var (
	// SLH-DSA SHA2 variants
	SLH_DSA_SHA2_128s Algo = slhdsaAlgo{params: slhdsa.SHA2_128s}.reg()
	SLH_DSA_SHA2_128f Algo = slhdsaAlgo{params: slhdsa.SHA2_128f}.reg()
	SLH_DSA_SHA2_192s Algo = slhdsaAlgo{params: slhdsa.SHA2_192s}.reg()
	SLH_DSA_SHA2_192f Algo = slhdsaAlgo{params: slhdsa.SHA2_192f}.reg()
	SLH_DSA_SHA2_256s Algo = slhdsaAlgo{params: slhdsa.SHA2_256s}.reg()
	SLH_DSA_SHA2_256f Algo = slhdsaAlgo{params: slhdsa.SHA2_256f}.reg()

	// SLH-DSA SHAKE variants
	SLH_DSA_SHAKE_128s Algo = slhdsaAlgo{params: slhdsa.SHAKE_128s}.reg()
	SLH_DSA_SHAKE_128f Algo = slhdsaAlgo{params: slhdsa.SHAKE_128f}.reg()
	SLH_DSA_SHAKE_192s Algo = slhdsaAlgo{params: slhdsa.SHAKE_192s}.reg()
	SLH_DSA_SHAKE_192f Algo = slhdsaAlgo{params: slhdsa.SHAKE_192f}.reg()
	SLH_DSA_SHAKE_256s Algo = slhdsaAlgo{params: slhdsa.SHAKE_256s}.reg()
	SLH_DSA_SHAKE_256f Algo = slhdsaAlgo{params: slhdsa.SHAKE_256f}.reg()
)

// String returns the algorithm name (e.g. "SLH-DSA-SHA2-128s").
func (a slhdsaAlgo) String() string {
	return a.params.String()
}

// Sign creates an SLH-DSA signature over the raw message. The private key
// must implement crypto.Signer with an *slhdsa.PublicKey.
func (a slhdsaAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	if _, ok := pk.Public().(*slhdsa.PublicKey); !ok {
		return nil, ErrInvalidSignKey
	}

	return pk.Sign(rand, buf, crypto.Hash(0))
}

// Verify verifies an SLH-DSA signature. If pub implements
// Public() crypto.PublicKey (e.g. a key wrapper), it will be unwrapped.
func (a slhdsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	if obj, ok := pub.(interface{ Public() crypto.PublicKey }); ok {
		pub = obj.Public()
	}

	pk, ok := pub.(*slhdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected *slhdsa.PublicKey, got %T", ErrInvalidPublicKey, pub)
	}

	if !pk.Verify(sign, buf, nil) {
		return ErrInvalidSignature
	}

	return nil
}

func (a slhdsaAlgo) reg() Algo {
	RegisterAlgo(a)
	return a
}
