package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type ecdsaAlgo int

var (
	DeprecatedAllowEcdsaASN1Signatures = true // this will turn to false eventually
)

func (h ecdsaAlgo) String() string {
	switch h {
	case ES224:
		return "ES224"
	case ES256:
		return "ES256"
	case ES256K:
		return "ES256K"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	default:
		return ""
	}
}

// digitLength returns the length of each R and S value in signatures for the given
// algorithm.
func (h ecdsaAlgo) digitLength() int {
	switch h.Hash() {
	case crypto.SHA224:
		return 28
	case crypto.SHA256:
		// ES256
		return 32
	case crypto.SHA384:
		// ES384
		return 48
	case crypto.SHA512:
		// ES512
		return 66
	}
	return 0
}

func (h ecdsaAlgo) Hash() crypto.Hash {
	switch h {
	case ES224:
		return crypto.SHA224
	case ES256, ES256K:
		return crypto.SHA256
	case ES384:
		return crypto.SHA384
	case ES512:
		return crypto.SHA512
	}
	return crypto.Hash(0)
}

func (h ecdsaAlgo) Sign(rand io.Reader, buf []byte, priv crypto.PrivateKey) ([]byte, error) {
	pk, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidSignKey
	}

	// ensure public key is a *ecdsa.PublicKey
	switch h {
	case ES256K:
		// skip test since we want to allow secp256k1 key, maybe just check the curve?
	default:
		if _, ok := pk.Public().(*ecdsa.PublicKey); !ok {
			return nil, ErrInvalidSignKey
		}
	}
	if !h.Hash().Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	buf, err := pk.Sign(rand, hash.Sum(nil), h.Hash())
	if err != nil {
		return nil, err
	}

	// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
	ln := h.digitLength()
	if len(buf) == ln*2 {
		// value is already good
		return buf, nil
	}

	// Sign() likely returned a ASN1 object, we need to decode it and return only R,S
	r, s, err := parseEcdsaSignature(buf)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA signature: %w", err)
	}

	if len(r) > ln || len(s) > ln {
		return nil, fmt.Errorf("bad data length for signature (length r=%d s=%d max=%d)", len(r), len(s), ln)
	}

	finalSig := make([]byte, ln*2)
	copy(finalSig[ln-len(r):ln], r)
	copy(finalSig[ln+ln-len(s):], s)
	return finalSig, nil
}

func (h ecdsaAlgo) Verify(buf, sign []byte, pub crypto.PublicKey) error {
	if obj, ok := pub.(interface{ Public() crypto.PublicKey }); ok {
		pub = obj.Public()
	}

	if !h.Hash().Available() {
		return fmt.Errorf("%w: %s", ErrHashNotAvailable, h.Hash().String())
	}

	hash := h.Hash().New()
	hash.Write(buf)

	ln := h.digitLength()

	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: unknown type %T", ErrInvalidPublicKey, pub)
	}
	if len(sign) != ln*2 {
		if DeprecatedAllowEcdsaASN1Signatures {
			// we're keeping this for now for backward compatibility - those signatures are not RFC7518 compliant
			if !ecdsa.VerifyASN1(pk, hash.Sum(nil), sign) {
				return ErrInvalidSignature
			}
		}
		return ErrInvalidSignatureLength
	}

	// proper ECDSA signature
	r := big.NewInt(0).SetBytes(sign[:ln])
	s := big.NewInt(0).SetBytes(sign[ln:])
	if !ecdsa.Verify(pk, hash.Sum(nil), r, s) {
		return ErrInvalidSignature
	}

	return nil
}

func (h ecdsaAlgo) reg() Algo {
	RegisterAlgo(h)
	return h
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/crypto/ecdsa/ecdsa.go;l=549
func parseEcdsaSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}
