[![GoDoc](https://godoc.org/github.com/KarpelesLab/jwt?status.svg)](https://godoc.org/github.com/KarpelesLab/jwt)

# Yet another jwt lib

This is a simple lib made for small footprint and easy usage

It allows creating and verifying jwt tokens easily.

## Why another jwt lib?

The main issue I have with [the existing JWT lib](https://github.com/golang-jwt/jwt) is that the syntax is too heavy.

## TODO

There are some things that still remain to be done:

* [ ] Implement more verification methods
* [ ] Test, test and test
* [ ] Write more documentation
* [ ] Support encrypted JWT tokens
* [ ] Apply Payload to go objects using reflect

# Examples

## Create & sign a new token

```go
import _ "crypto/sha256"

priv := []byte("this is a hmac key")
tok := jwt.New(jwt.HS256)
tok.Header().Set("kid", keyId) // syntax to set header values
tok.Payload().Set("iss", "myself")
tok.Payload().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
sign, err := tok.Sign(priv)
```

## Verify a token

```go
import _ "crypto/sha256"

token, err := jwt.ParseString(input)
if err != nil {
	...
}
publicKey := fetchPublicKey(token.GetKeyId())
err = token.Verify(jwt.VerifyAlgo(jwt.ES256, jwt.RS256), jwt.VerifySignature(publicKey), jwt.VerifyExpiresAt(time.Now(), false))
if err != nil {
	...
}
log.Printf("token iss value = %s", token.Payload().Get("iss"))
```

## Create a non-json token

```go
import _ "crypto/sha256"

priv := []byte("this is a hmac key")
tok := jwt.New(jwt.HS256)
tok.Header().Set("kid", keyId)
tok.SetRawPayload(binData, "octet-stream") // can pass cty="" to not set content type
sign, err := tok.Sign(priv)
```
