[![GoDoc](https://godoc.org/github.com/KarpelesLab/jwt?status.svg)](https://godoc.org/github.com/KarpelesLab/jwt)
[![Build Status](https://github.com/KarpelesLab/jwt/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/jwt/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/jwt/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/jwt?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/jwt)](https://goreportcard.com/report/github.com/KarpelesLab/jwt)

# jwt

A lightweight Go library for creating, signing, verifying, encrypting and decrypting JSON Web Tokens.

Supports JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) for signed tokens and JWE ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) for encrypted tokens, including post-quantum algorithms.

## Features

- **Simple API** -- create, sign, verify and encrypt tokens in a few lines
- **JWS signing** -- HMAC, RSA, RSA-PSS, ECDSA, Ed25519, ML-DSA, SLH-DSA
- **JWE encryption** -- RSA-OAEP, ECDH-ES, AES Key Wrap, direct keys, ML-KEM
- **Post-quantum ready** -- ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203)
- **Custom algorithms** -- implement `Algo`, `KeyAlgo` or `EncAlgo` and register
- **JWK support** -- parse, export and use JSON Web Keys (RFC 7517)
- **No magic** -- works directly with `crypto.Signer`, `crypto.PublicKey` and `[]byte` keys
- **Hardware-friendly** -- any `crypto.Signer` or `crypto.Decrypter` works (HSMs, KMS, etc.)

## JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication). It's commonly used for `Bearer` tokens in Oauth 2. A token is made of three parts, separated by `.`'s. The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded. The last part is the signature, encoded the same way.

The first part is called the header. It contains the necessary information for verifying the last part, the signature. For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit. It's called the Claims and contains the actual stuff you care about. Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.

## Supported algorithms

### JWS signing algorithms

| Family | Algorithms |
|--------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES224, ES256, ES384, ES512, ES256K |
| EdDSA | Ed25519 |
| ML-DSA (PQ) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA (PQ) | All SHA2 and SHAKE variants at 128/192/256 security levels |
| None | `none` (signing produces no signature; verification always fails) |

### JWE key management algorithms

| Algorithm | Description |
|-----------|-------------|
| RSA-OAEP | RSA-OAEP with SHA-1 |
| RSA-OAEP-256 | RSA-OAEP with SHA-256 |
| A128KW, A192KW, A256KW | AES Key Wrap (RFC 3394) |
| ECDH-ES | ECDH Ephemeral Static key agreement (RFC 7518) |
| ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW | ECDH-ES with AES Key Wrap |
| dir | Direct use of a shared symmetric key |
| ML-KEM-768, ML-KEM-1024 | Post-quantum key encapsulation (FIPS 203) |

### JWE content encryption algorithms

| Algorithm | Description |
|-----------|-------------|
| A128GCM, A192GCM, A256GCM | AES-GCM |
| A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 | AES-CBC + HMAC-SHA2 |

## Installation

```
go get github.com/KarpelesLab/jwt
```

Requires Go 1.24 or later (for `crypto/mlkem`).

## Examples

### Create & sign a token

```go
import _ "crypto/sha256"

priv := []byte("this is a hmac key")
tok := jwt.New(jwt.HS256)
tok.Header().Set("kid", keyId)
tok.Payload().Set("iss", "myself")
tok.Payload().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
signedToken, err := tok.Sign(rand.Reader, priv)
```

### Verify a token

```go
import _ "crypto/sha256"

token, err := jwt.ParseString(input)
if err != nil {
	// handle error
}
publicKey := fetchPublicKey(token.GetKeyId())
err = token.Verify(
	jwt.VerifyAlgo(jwt.ES256, jwt.RS256),
	jwt.VerifySignature(publicKey),
	jwt.VerifyExpiresAt(time.Now(), false),
)
if err != nil {
	// handle error
}
log.Printf("token iss value = %s", token.Payload().Get("iss"))
```

### Auto-detect algorithm from key

```go
// The algorithm is inferred from the key type
tok := jwt.New()
tok.Payload().Set("sub", "user123")
signed, err := tok.Sign(rand.Reader, ecdsaPrivateKey)
// tok.GetAlgo().String() == "ES256" (for P-256 keys)
```

### Encrypt a token (JWE)

```go
tok := jwt.New()
tok.Payload().Set("sub", "user123")
encrypted, err := tok.Encrypt(rand.Reader, recipientPublicKey, nil) // auto-detects RSA-OAEP-256 + A256GCM
```

### Decrypt a token (JWE)

```go
tok, err := jwt.ParseString(encrypted)
if err != nil {
	// handle error
}
err = tok.Decrypt(recipientPrivateKey)
if err != nil {
	// handle error
}
log.Printf("sub = %s", tok.Payload().GetString("sub"))
```

### Encrypt with ECDH-ES

```go
// Using crypto/ecdh keys — algorithm auto-detected as ECDH-ES
key, _ := ecdh.P256().GenerateKey(rand.Reader)

tok := jwt.New()
tok.Payload().Set("sub", "user123")
encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), nil)

// Decrypt
tok2, _ := jwt.ParseString(encrypted)
err = tok2.Decrypt(key)

// ECDSA keys are also supported — they are converted automatically
ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
encrypted, err = tok.Encrypt(rand.Reader, &ecdsaKey.PublicKey, nil)

// Use ECDH-ES+A256KW key wrapping with explicit options
encrypted, err = tok.Encrypt(rand.Reader, &ecdsaKey.PublicKey, &jwt.EncryptOptions{KeyAlgo: jwt.ECDH_ES_A256KW})
```

### Encrypt with a symmetric key

```go
key := make([]byte, 32) // 256-bit key for A256GCM
rand.Read(key)

tok := jwt.New()
tok.Payload().Set("msg", "secret")
encrypted, err := tok.Encrypt(rand.Reader, key, nil) // auto-detects dir + A256GCM

// Decrypt
tok2, _ := jwt.ParseString(encrypted)
err = tok2.Decrypt(key)
```

### Post-quantum signing (ML-DSA)

```go
key, _ := mldsa.GenerateKey65(rand.Reader)

tok := jwt.New(jwt.MLDSA65)
tok.Payload().Set("sub", "pq-user")
signed, err := tok.Sign(rand.Reader, key)

// Verify
tok2, _ := jwt.ParseString(signed)
err = tok2.Verify(jwt.VerifyAlgo(jwt.MLDSA65), jwt.VerifySignature(key.PublicKey()))
```

### Post-quantum encryption (ML-KEM)

```go
dk, _ := mlkem.GenerateKey768()

tok := jwt.New()
tok.Payload().Set("msg", "quantum-safe")
encrypted, err := tok.Encrypt(rand.Reader, dk.EncapsulationKey(), nil) // auto-detects ML-KEM-768 + A256GCM

// Decrypt
tok2, _ := jwt.ParseString(encrypted)
err = tok2.Decrypt(dk)
```

### Non-JSON payload

```go
import _ "crypto/sha256"

priv := []byte("this is a hmac key")
tok := jwt.New(jwt.HS256)
tok.Header().Set("kid", keyId)
tok.SetRawPayload(binData, "octet-stream") // can pass cty="" to not set content type
signedToken, err := tok.Sign(rand.Reader, priv)
```

## Verification options

| Function | Description |
|----------|-------------|
| `VerifyAlgo(algo...)` | Ensures the token uses one of the specified algorithms |
| `VerifySignature(key)` | Verifies the token's signature against a public key or shared secret |
| `VerifyExpiresAt(now, required)` | Checks the `exp` claim |
| `VerifyNotBefore(now, required)` | Checks the `nbf` claim |
| `VerifyTime(now, required)` | Checks both `exp` and `nbf` |
| `VerifyMultiple(opts...)` | Combines multiple checks |

## Why this library?

The main issue I have with [the existing JWT lib](https://github.com/golang-jwt/jwt) is that the syntax is too heavy and I had something else in mind in terms of what would make a convenient JWT lib. I've had also issues with it performing checks on incoming `crypto.Signer` objects that prevent third party signature providers such as hardware modules, and a few other things. JWT is a simple enough standard so building a new lib isn't that much work.

All signature algorithms are always linked (hmac, rsa, ecdsa, ed25519, mldsa, slhdsa). These are also pulled by Go's `crypto/x509` so you probably have most of them compiled in already.
