package jwt

import "errors"

var (
	ErrInvalidToken = errors.New("jwt: invalid token provided")
)
