package jwt

import (
	"crypto"
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
		sign, err := tok.GetRawSignature()
		if err != nil {
			return fmt.Errorf("jwt: failed to read signature: %w", err)
		}

		// pub is typically one of *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
		algo := tok.GetAlgo()
		if algo == nil {
			return ErrInvalidToken // unsupported algo
		}

		return algo.Verify(tok.GetSignString(), sign, pub)
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

		// exp date is before now, it means it's in the past
		if exp.Before(now) {
			return fmt.Errorf("%w: token has expired", ErrVerifyFailed)
		}
		return nil
	}
}

// VerifyNotBefore returns a VerifyOption that will check the token's
// not before claim (nbf).
//
// Example use: VerifyNotBefore(time.Now(), false)
func VerifyNotBefore(now time.Time, req bool) VerifyOption {
	return func(tok *Token) error {
		if !tok.Payload().Has("nbf") {
			if req {
				return fmt.Errorf("%w: NotBefore claim", ErrVerifyMissing)
			}
			return nil
		}
		nbf := tok.Payload().GetNumericDate("nbf")

		if now.Before(nbf) {
			return fmt.Errorf("%w: token is not valid yet (nbf claim)", ErrVerifyFailed)
		}
		return nil
	}
}

// VerifyTime will verify both the not before and the expires at claims
func VerifyTime(now time.Time, req bool) VerifyOption {
	return VerifyMultiple(VerifyExpiresAt(now, req), VerifyNotBefore(now, req))
}

// VerifyMultiple compounds multiple conditions and fails if any of the passed
// condition fails.
func VerifyMultiple(opts ...VerifyOption) VerifyOption {
	return func(tok *Token) error {
		for _, opt := range opts {
			if err := opt(tok); err != nil {
				return err
			}
		}
		return nil
	}
}
