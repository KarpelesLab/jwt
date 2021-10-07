package jwt

import "errors"

var (
	ErrInvalidToken     = errors.New("jwt: invalid token provided")
	ErrNoSignature      = errors.New("jwt: token has no signature")
	ErrInvalidSignature = errors.New("jwt: token signature is not valid")
)
