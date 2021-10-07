[![GoDoc](https://godoc.org/github.com/KarpelesLab/jwt?status.svg)](https://godoc.org/github.com/KarpelesLab/jwt)

# Yet another jwt lib

This is a simple lib made for small footprint and easy usage

It allows creating and verifying jwt tokens easily.

## Why another jwt lib?

The main issue I have with [the existing JWT lib](https://github.com/golang-jwt/jwt) is that the syntax is too heavy.

# Examples

## Create & sign a new token

```go
priv := []byte("this is a hmac key")
tok := jwt.New(jwt.HS256)
tok.Header().Set("typ", "JWT") // syntax to set header values
tok.Body().Set("iss", "myself")
tok.Body().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
sign, err := tok.Sign(priv)
```

## Verify a token

```go
token, err := jwt.ParseString(input)
if err != nil {
	...
}
publicKey := fetchPublicKey(token.GetKeyId())
err = token.Verify(publicKey)
if err != nil {
	...
}
log.Printf("token iss value = %s", token.Body().Get("iss"))
```
