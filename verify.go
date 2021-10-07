package jwt

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"time"
)

type VerifyOption func(*Token) error

func VerifyAlgo(algo ...Algo) VerifyOption {
	return func(tok *Token) error {
		tokAlgo := tok.GetAlgo()
		if tokAlgo == nil {
			return ErrInvalidToken
		}

		// compare algo string in case we have two instances of the same object
		name := tokAlgo.String()

		for _, a := range algo {
			// do we need constant time compare here?
			if name == a.String() {
				return nil
			}
		}

		return fmt.Errorf("%w: unexpected signature algorithm %s", ErrVerifyFailed, tokAlgo)
	}
}

func VerifySignature(pub crypto.PublicKey) VerifyOption {
	return func(tok *Token) error {
		if len(tok.values) < 3 {
			return ErrNoSignature
		}
		sign, err := base64.RawURLEncoding.DecodeString(tok.values[2])
		if err != nil {
			return fmt.Errorf("jwt: failed to read signature: %w", err)
		}

		// pub is typically one of *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
		algo := tok.GetAlgo()
		if algo == nil {
			return ErrInvalidToken // unsupported algo
		}

		return algo.Verify(tok.getSignString(), sign, pub)
	}
}

// VerifyExpiresAt returns a VerifyOption that will check the token's
// expiration to not be before now.
//
// Example use: VerifyExpiresAt(time.Now(), false)
func VerifyExpiresAt(now time.Time, req bool) VerifyOption {
	return func(t *Token) error {
		if !t.Payload().Has("exp") {
			if req {
				return fmt.Errorf("%w: ExpiresAt claim", ErrVerifyMissing)
			}
			return nil
		}
		exp := t.Payload().GetNumericDate("exp")

		if exp.Before(now) {
			return fmt.Errorf("%w: token has expired", ErrVerifyFailed)
		}
		return nil
	}
}
