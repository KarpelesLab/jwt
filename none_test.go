package jwt_test

import (
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestNone(t *testing.T) {
	tok := jwt.New(jwt.None)
	tok.Payload().Set("iss", "test")

	signed, err := tok.Sign(nil, nil)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	if signed == "" {
		t.Fatal("signed token is empty")
	}

	// verify should always fail for none algo
	err = tok.Verify(jwt.VerifySignature(nil))
	if err == nil {
		t.Error("none algo verification should always fail")
	}
}
