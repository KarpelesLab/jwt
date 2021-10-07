package jwt_test

import (
	_ "crypto/sha256"
	"log"
	"testing"
	"time"

	"github.com/KarpelesLab/jwt"
)

func TestHmac(t *testing.T) {
	priv := []byte("this is a hmac key")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "myself")
	tok.Payload().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
	sign, err := tok.Sign(priv)

	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	log.Printf("signed: %s", sign)

	tok2, err := jwt.ParseString(sign)
	if err != nil {
		t.Fatalf("failed to read signed: %s", err)
	}

	err = tok2.Verify(jwt.VerifyAlgo(jwt.HS256, jwt.ES256), jwt.VerifySignature(priv), jwt.VerifyExpiresAt(time.Now(), true))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}

	// this should fail
	err = tok2.Verify(jwt.VerifyExpiresAt(time.Now().Add(366*24*time.Hour), false))
	if err == nil {
		t.Errorf("failed to trigger verification failure: %s", err)
	}

	if tok2.Payload().Get("iss").(string) != "myself" {
		t.Errorf("invalid value in body")
	}
}

func TestHmacParse(t *testing.T) {
	priv := []byte("secretkey")
	tok, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI")
	if err != nil {
		t.Fatalf("failed to parse token: %s", err)
	}

	err = tok.Verify(jwt.VerifySignature(priv))
	if err != nil {
		t.Fatalf("failed to verify token: %s", err)
	}

	if tok.Payload().Get("loggedInAs").(string) != "admin" {
		t.Errorf("invalid value in body")
	}
}
