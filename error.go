package jwt

import "errors"

var (
	ErrInvalidToken           = errors.New("jwt: invalid token provided")
	ErrNoSignature            = errors.New("jwt: token has no signature")
	ErrInvalidSignature       = errors.New("jwt: token signature is not valid")
	ErrInvalidSignKey         = errors.New("jwt: invalid key provided for signature")
	ErrInvalidSignatureLength = errors.New("jwt: token signature is not valid (bad length)")
	ErrHashNotAvailable       = errors.New("jwt: hash method not available")
	ErrNoHeader               = errors.New("jwt: header is not available (parsing failed?)")
	ErrNoPayload              = errors.New("jwt: payload is not available (parsing failed?)")

	ErrVerifyMissing = errors.New("jwt: a claim required for verification is missing")
	ErrVerifyFailed  = errors.New("jwt: claim verification has failed")
)
