package jwt_test

import (
	_ "crypto/sha256"
	"testing"
	"time"

	"github.com/KarpelesLab/jwt"
)

func TestVerifyNotBefore(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "test")
	tok.Payload().Set("nbf", time.Now().Add(-time.Hour).Unix())
	tok.Sign(nil, priv)

	// nbf is in the past, should pass
	err := tok.Verify(jwt.VerifyNotBefore(time.Now(), false))
	if err != nil {
		t.Errorf("should pass when nbf is in the past: %s", err)
	}

	// nbf is in the future, should fail
	tok2 := jwt.New(jwt.HS256)
	tok2.Payload().Set("nbf", time.Now().Add(time.Hour).Unix())
	tok2.Sign(nil, priv)

	err = tok2.Verify(jwt.VerifyNotBefore(time.Now(), false))
	if err == nil {
		t.Error("should fail when nbf is in the future")
	}
}

func TestVerifyNotBeforeRequired(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "test")
	tok.Sign(nil, priv)

	// nbf not set, required=true
	err := tok.Verify(jwt.VerifyNotBefore(time.Now(), true))
	if err == nil {
		t.Error("should fail when nbf is required but missing")
	}

	// nbf not set, required=false
	err = tok.Verify(jwt.VerifyNotBefore(time.Now(), false))
	if err != nil {
		t.Errorf("should pass when nbf is not required: %s", err)
	}
}

func TestVerifyExpiresAtRequired(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "test")
	tok.Sign(nil, priv)

	// exp not set, required=true
	err := tok.Verify(jwt.VerifyExpiresAt(time.Now(), true))
	if err == nil {
		t.Error("should fail when exp is required but missing")
	}

	// exp not set, required=false
	err = tok.Verify(jwt.VerifyExpiresAt(time.Now(), false))
	if err != nil {
		t.Errorf("should pass when exp is not required: %s", err)
	}
}

func TestVerifyTime(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("nbf", time.Now().Add(-time.Hour).Unix())
	tok.Payload().Set("exp", time.Now().Add(time.Hour).Unix())
	tok.Sign(nil, priv)

	err := tok.Verify(jwt.VerifyTime(time.Now(), true))
	if err != nil {
		t.Errorf("VerifyTime should pass: %s", err)
	}

	// expired
	tok2 := jwt.New(jwt.HS256)
	tok2.Payload().Set("nbf", time.Now().Add(-2*time.Hour).Unix())
	tok2.Payload().Set("exp", time.Now().Add(-time.Hour).Unix())
	tok2.Sign(nil, priv)

	err = tok2.Verify(jwt.VerifyTime(time.Now(), true))
	if err == nil {
		t.Error("VerifyTime should fail for expired token")
	}
}

func TestVerifyMultiple(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "test")
	tok.Payload().Set("exp", time.Now().Add(time.Hour).Unix())
	tok.Sign(nil, priv)

	// all pass
	err := tok.Verify(jwt.VerifyMultiple(
		jwt.VerifyAlgo(jwt.HS256),
		jwt.VerifySignature(priv),
		jwt.VerifyExpiresAt(time.Now(), true),
	))
	if err != nil {
		t.Errorf("VerifyMultiple should pass: %s", err)
	}

	// empty multiple should pass
	err = tok.Verify(jwt.VerifyMultiple())
	if err != nil {
		t.Errorf("empty VerifyMultiple should pass: %s", err)
	}
}

func TestVerifyAlgoMismatch(t *testing.T) {
	priv := []byte("secret")
	tok := jwt.New(jwt.HS256)
	tok.Payload().Set("iss", "test")
	tok.Sign(nil, priv)

	err := tok.Verify(jwt.VerifyAlgo(jwt.ES256, jwt.RS256))
	if err == nil {
		t.Error("should fail with algo mismatch")
	}
}
