package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"testing"
	"time"

	"github.com/KarpelesLab/jwt"
)

func TestRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}

	for _, algo := range []jwt.Algo{jwt.RS256, jwt.RS384, jwt.RS512} {
		t.Run(algo.String(), func(t *testing.T) {
			tok := jwt.New(algo)
			tok.Payload().Set("iss", "test")
			tok.Payload().Set("exp", time.Now().Add(time.Hour).Unix())

			signed, err := tok.Sign(rand.Reader, key)
			if err != nil {
				t.Fatalf("failed to sign: %s", err)
			}
			if signed == "" {
				t.Fatal("signed token is empty")
			}

			// verify with public key
			err = tok.Verify(jwt.VerifyAlgo(algo), jwt.VerifySignature(&key.PublicKey))
			if err != nil {
				t.Errorf("failed to verify: %s", err)
			}

			// parse and verify
			tok2, err := jwt.ParseString(signed)
			if err != nil {
				t.Fatalf("failed to parse: %s", err)
			}
			err = tok2.Verify(jwt.VerifySignature(&key.PublicKey))
			if err != nil {
				t.Errorf("parsed token failed to verify: %s", err)
			}

			// verify with wrong key should fail
			key2, _ := rsa.GenerateKey(rand.Reader, 2048)
			err = tok2.Verify(jwt.VerifySignature(&key2.PublicKey))
			if err == nil {
				t.Error("verification should have failed with wrong key")
			}
		})
	}
}

func TestRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}

	for _, algo := range []jwt.Algo{jwt.PS256, jwt.PS384, jwt.PS512} {
		t.Run(algo.String(), func(t *testing.T) {
			tok := jwt.New(algo)
			tok.Payload().Set("iss", "test")

			signed, err := tok.Sign(rand.Reader, key)
			if err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			err = tok.Verify(jwt.VerifySignature(&key.PublicKey))
			if err != nil {
				t.Errorf("failed to verify: %s", err)
			}

			// parse and verify
			tok2, err := jwt.ParseString(signed)
			if err != nil {
				t.Fatalf("failed to parse: %s", err)
			}
			err = tok2.Verify(jwt.VerifySignature(&key.PublicKey))
			if err != nil {
				t.Errorf("parsed token failed to verify: %s", err)
			}
		})
	}
}

func TestRSASignInvalidKey(t *testing.T) {
	tok := jwt.New(jwt.RS256)
	tok.Payload().Set("iss", "test")

	// wrong key type
	_, err := tok.Sign(rand.Reader, []byte("not an rsa key"))
	if err == nil {
		t.Error("should fail with non-RSA key")
	}
}

func TestRSAVerifyInvalidKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := jwt.New(jwt.RS256)
	tok.Payload().Set("iss", "test")
	tok.Sign(rand.Reader, key)

	// verify with wrong key type
	err := tok.Verify(jwt.VerifySignature([]byte("wrong")))
	if err == nil {
		t.Error("should fail with non-RSA public key")
	}
}

func TestRSAJWK(t *testing.T) {
	rsaJwk := parseJwk([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`))

	tok := jwt.New(jwt.RS256)
	tok.Payload().Set("iss", "test")

	// can't sign with public-only JWK
	_, err := tok.Sign(rand.Reader, rsaJwk)
	if err == nil {
		t.Error("should fail to sign with public-only JWK")
	}
}
