package jwt_test

import (
	"log"
	"testing"
	"time"

	"github.com/KarpelesLab/jwt"
)

var (
	Alice = parseJwk([]byte(`{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps","d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}`))
	Bob   = parseJwk([]byte(`{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`))
)

func parseJwk(jwk []byte) *jwt.JWK {
	k := &jwt.JWK{}
	err := k.UnmarshalJSON(jwk)
	if err != nil {
		panic(err)
	}
	return k
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for n := range b {
		b[n] = 0
	}
	return len(b), nil
}

func TestECDSA(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("iss", "myself")
	tok.Payload().Set("exp", time.Now().Add(365*24*time.Hour).Unix())
	sign, err := tok.Sign(zeroReader{}, Alice)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
		return
	}
	log.Printf("signed = %s", sign)

	// test signature
	err = tok.Verify(jwt.VerifySignature(Alice))
	if err != nil {
		t.Errorf("unable to verify signature of generated token: %s", err)
	}
}
