[![GoDoc](https://godoc.org/github.com/KarpelesLab/jwt?status.svg)](https://godoc.org/github.com/KarpelesLab/jwt)

# Yet another jwt lib

This is a simple lib made for small footprint and easy usage

It allows creating, signing, reading and verifying jwt tokens easily (see code examples below).

## JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication). It's commonly used for `Bearer` tokens in Oauth 2. A token is made of three parts, separated by `.`'s. The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded. The last part is the signature, encoded the same way.

The first part is called the header. It contains the necessary information for verifying the last part, the signature. For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit. It's called the Claims and contains the actual stuff you care about. Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.

(courtesy of [golang-jwt](https://github.com/golang-jwt/jwt#what-the-heck-is-a-jwt)).

## Why another jwt lib?

The main issue I have with [the existing JWT lib](https://github.com/golang-jwt/jwt) is that the syntax is too heavy and I had something else in mind in terms of what would make a convenient JWT lib. I've had also issues with it performing checks on incoming `crypto.Signer` objects that prevent third party signature providers such has hardware modules, and a few other things. JWT is a simple enough standard so building a new lib isn't that much work.

Note that all algos are always linked (hmac, rsa, ecdsa, ed25519). All libs are also pulled by go's `crypto/x509` so you probably have these already compiled in. If go decides to avoid building these in, then I will move these in submodules, but for now there is no need to do so.

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
signedToken, err := tok.Sign(priv)
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
signedToken, err := tok.Sign(priv)
```
