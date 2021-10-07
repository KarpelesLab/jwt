package jwt

import "errors"

var (
	ErrInvalidToken     = errors.New("jwt: invalid token provided")
	ErrNoSignature      = errors.New("jwt: token has no signature")
	ErrInvalidSignature = errors.New("jwt: token signature is not valid")
	ErrInvalidSignKey   = errors.New("jwt: invalid key provided for signature")
	ErrHashNotAvailable = errors.New("jwt: hash method not available")
	ErrNoHeader         = errors.New("jwt: header is not available (parsing failed?)")
	ErrNoBody           = errors.New("jwt: body is not available (parsing failed?)")
)
