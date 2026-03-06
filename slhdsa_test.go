package jwt_test

import (
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/jwt"
	"github.com/KarpelesLab/slhdsa"
)

func TestSLHDSA_SHA2_128s(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.SLH_DSA_SHA2_128s)
	tok.Payload().Set("sub", "slh-user")

	signed, err := tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Verify(
		jwt.VerifyAlgo(jwt.SLH_DSA_SHA2_128s),
		jwt.VerifySignature(key.Public()),
	)
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}

	if tok2.Payload().GetString("sub") != "slh-user" {
		t.Error("payload mismatch")
	}
}

func TestSLHDSA_SHAKE_256s(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_256s)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.SLH_DSA_SHAKE_256s)
	tok.Payload().Set("level", "5")

	signed, err := tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Verify(jwt.VerifySignature(key.Public()))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}
}

func TestSLHDSAAutoDetect(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	// Sign without specifying algo — should auto-detect
	tok := jwt.New()
	tok.Payload().Set("sub", "auto")
	_, err = tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign with auto-detected algo: %s", err)
	}

	algo := tok.GetAlgo()
	if algo == nil || algo.String() != "SLH-DSA-SHA2-128s" {
		t.Errorf("expected SLH-DSA-SHA2-128s, got %v", algo)
	}
}

func TestSLHDSAInvalidKeyType(t *testing.T) {
	tok := jwt.New(jwt.SLH_DSA_SHA2_128s)
	tok.Payload().Set("sub", "test")

	_, err := tok.Sign(rand.Reader, []byte("not a key"))
	if err == nil {
		t.Error("should fail with invalid key type")
	}
}

func TestSLHDSAWrongKey(t *testing.T) {
	key1, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	key2, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)

	tok := jwt.New(jwt.SLH_DSA_SHA2_128s)
	tok.Payload().Set("sub", "test")
	tok.Sign(rand.Reader, key1)

	err := tok.Verify(jwt.VerifySignature(key2.Public()))
	if err == nil {
		t.Error("should fail with wrong key")
	}
}
