package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New(jwt.EdDSA)
	tok.Payload().Set("iss", "test")

	signed, err := tok.Sign(rand.Reader, priv)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	if signed == "" {
		t.Fatal("signed token is empty")
	}

	// verify
	err = tok.Verify(jwt.VerifyAlgo(jwt.EdDSA), jwt.VerifySignature(pub))
	if err != nil {
		t.Errorf("failed to verify: %s", err)
	}

	// parse and verify
	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	err = tok2.Verify(jwt.VerifySignature(pub))
	if err != nil {
		t.Errorf("parsed token failed to verify: %s", err)
	}

	// wrong key should fail
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	err = tok2.Verify(jwt.VerifySignature(priv2.Public()))
	if err == nil {
		t.Error("verification should have failed with wrong key")
	}
}

func TestEd25519SignInvalidKey(t *testing.T) {
	tok := jwt.New(jwt.EdDSA)
	tok.Payload().Set("iss", "test")

	_, err := tok.Sign(rand.Reader, []byte("not a key"))
	if err == nil {
		t.Error("should fail with invalid key type")
	}
}

func TestEd25519VerifyInvalidKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok := jwt.New(jwt.EdDSA)
	tok.Payload().Set("iss", "test")
	tok.Sign(rand.Reader, priv)

	err := tok.Verify(jwt.VerifySignature([]byte("wrong")))
	if err == nil {
		t.Error("should fail with invalid public key type")
	}
}

func TestEd25519AlgoDetection(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// sign without specifying algo — should auto-detect EdDSA
	tok := jwt.New()
	tok.Payload().Set("iss", "test")
	_, err := tok.Sign(rand.Reader, priv)
	if err != nil {
		t.Fatalf("failed to sign with auto-detected algo: %s", err)
	}

	algo := tok.GetAlgo()
	if algo == nil || algo.String() != "EdDSA" {
		t.Errorf("expected EdDSA algo, got %v", algo)
	}
}
