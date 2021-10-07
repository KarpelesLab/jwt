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
	tok.Body().Set("iss", "myself")
	tok.Body().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
	sign, err := tok.Sign(priv)

	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	log.Printf("signed: %s", sign)

	tok2, err := jwt.ParseString(sign)
	if err != nil {
		t.Fatalf("failed to read signed: %s", err)
	}

	err = tok2.Verify(priv)
	if err != nil {
		t.Fatalf("failed to verify: %s", err)
	}

	body := tok2.Body()
	if body == nil {
		t.Fatalf("failed to read body: %s", err)
	}

	if body.IsExpired(true) {
		t.Errorf("body is expired!")
	}

	if tok2.Body().Get("iss").(string) != "myself" {
		t.Errorf("invalid value in body")
	}
}

func TestHmacParse(t *testing.T) {
	priv := []byte("secretkey")
	tok, err := jwt.ParseString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI")
	if err != nil {
		t.Fatalf("failed to parse token: %s", err)
	}

	err = tok.Verify(priv)
	if err != nil {
		t.Fatalf("failed to verify token: %s", err)
	}

	if tok.Body().Get("loggedInAs").(string) != "admin" {
		t.Errorf("invalid value in body")
	}
}
