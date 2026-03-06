package jwt_test

import (
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/jwt"
	"github.com/KarpelesLab/mldsa"
)

func TestMLDSA44(t *testing.T) {
	key, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.MLDSA44)
	tok.Payload().Set("sub", "pq-user")

	signed, err := tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Verify(jwt.VerifyAlgo(jwt.MLDSA44), jwt.VerifySignature(key.PublicKey()))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}
}

func TestMLDSA65(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.MLDSA65)
	tok.Payload().Set("sub", "pq-user-65")

	signed, err := tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Verify(jwt.VerifyAlgo(jwt.MLDSA65), jwt.VerifySignature(key.PublicKey()))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}

	if tok2.Payload().GetString("sub") != "pq-user-65" {
		t.Error("payload mismatch")
	}
}

func TestMLDSA87(t *testing.T) {
	key, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.MLDSA87)
	tok.Payload().Set("sub", "pq-user-87")

	signed, err := tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Verify(jwt.VerifyAlgo(jwt.MLDSA87), jwt.VerifySignature(key.PublicKey()))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}
}

func TestMLDSAAutoDetect(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	// Sign without specifying algo — should auto-detect ML-DSA-65
	tok := jwt.New()
	tok.Payload().Set("sub", "auto")
	_, err = tok.Sign(rand.Reader, key)
	if err != nil {
		t.Fatalf("failed to sign with auto-detected algo: %s", err)
	}

	algo := tok.GetAlgo()
	if algo == nil || algo.String() != "ML-DSA-65" {
		t.Errorf("expected ML-DSA-65, got %v", algo)
	}
}

func TestMLDSAWrongKey(t *testing.T) {
	key44, _ := mldsa.GenerateKey44(rand.Reader)
	key65, _ := mldsa.GenerateKey65(rand.Reader)

	tok := jwt.New(jwt.MLDSA65)
	tok.Payload().Set("sub", "test")
	tok.Sign(rand.Reader, key65)

	// Verify with wrong level key should fail
	err := tok.Verify(jwt.VerifySignature(key44.PublicKey()))
	if err == nil {
		t.Error("should fail with wrong key level")
	}
}

func TestMLDSAInvalidKeyType(t *testing.T) {
	tok := jwt.New(jwt.MLDSA65)
	tok.Payload().Set("sub", "test")

	_, err := tok.Sign(rand.Reader, []byte("not a key"))
	if err == nil {
		t.Error("should fail with invalid key type")
	}
}
