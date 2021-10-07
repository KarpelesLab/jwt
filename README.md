[![GoDoc](https://godoc.org/github.com/KarpelesLab/jwt?status.svg)](https://godoc.org/github.com/KarpelesLab/jwt)

# Yet another jwt lib

This is a simple lib made for small footprint and easy usage

It allows creating and verifying jwt tokens easily.

# Examples

## Create & sign a new token

	priv := []byte("this is a hmac key")
	tok := jwt.New(jwt.HS256)
	tok.Set("iss", "myself")
	tok.Set("exp", time.Now().Add(365*24*time.Hour).Unix())
	sign, err := tok.Sign(priv)
