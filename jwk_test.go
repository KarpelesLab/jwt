package jwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestJWKMarshalRSAPublic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	jwk := &jwt.JWK{
		PublicKey: &key.PublicKey,
		KeyID:     "rsa-test",
		Algo:      "RS256",
		Use:       "sig",
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	var jwk2 jwt.JWK
	err = json.Unmarshal(data, &jwk2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %s", err)
	}

	if jwk2.KeyID != "rsa-test" {
		t.Errorf("expected kid=rsa-test, got %s", jwk2.KeyID)
	}
	if jwk2.Algo != "RS256" {
		t.Errorf("expected alg=RS256, got %s", jwk2.Algo)
	}
	if jwk2.Use != "sig" {
		t.Errorf("expected use=sig, got %s", jwk2.Use)
	}
	if jwk2.PublicKey == nil {
		t.Error("public key should be set")
	}
}

func TestJWKMarshalRSAPrivate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	jwk := &jwt.JWK{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		KeyID:      "rsa-priv",
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	// exported JSON should contain d (private key field)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["d"] == nil {
		t.Error("exported RSA private key should contain d")
	}
	if raw["kty"] != "RSA" {
		t.Error("expected kty=RSA")
	}
}

func TestJWKMarshalECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	jwk := &jwt.JWK{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		KeyID:      "ec-test",
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}

	var jwk2 jwt.JWK
	err = json.Unmarshal(data, &jwk2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %s", err)
	}

	if jwk2.KeyID != "ec-test" {
		t.Errorf("expected kid=ec-test, got %s", jwk2.KeyID)
	}
	if jwk2.PrivateKey == nil {
		t.Error("private key should be set")
	}
}

func TestJWKPublicOnlyRSA(t *testing.T) {
	jwk := parseJwk([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","kid":"rsa-pub"}`))

	if jwk.KeyID != "rsa-pub" {
		t.Errorf("expected kid=rsa-pub, got %s", jwk.KeyID)
	}
	if jwk.PrivateKey != nil {
		t.Error("should not have private key")
	}
	if jwk.PublicKey == nil {
		t.Error("should have public key")
	}

	pub := jwk.Public()
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestJWKPublicOnlyECDSA(t *testing.T) {
	jwk := parseJwk([]byte(`{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}`))

	if jwk.PrivateKey != nil {
		t.Error("should not have private key")
	}
	if jwk.PublicKey == nil {
		t.Error("should have public key")
	}
}

func TestJWKThumbprint(t *testing.T) {
	jwk := parseJwk([]byte(`{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}`))

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint failed: %s", err)
	}
	if len(tp) != sha256.Size {
		t.Errorf("expected %d bytes, got %d", sha256.Size, len(tp))
	}

	hex := jwk.ThumbprintHex(crypto.SHA256)
	if hex == "" {
		t.Error("ThumbprintHex should not be empty")
	}
}

func TestJWKString(t *testing.T) {
	jwk := parseJwk([]byte(`{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}`))
	s := jwk.String()
	if s == "" {
		t.Error("String() should not be empty")
	}

	// with private key
	s = Alice.String()
	if s == "" {
		t.Error("String() with private key should not be empty")
	}
}

func TestJWKExportValues(t *testing.T) {
	jwk := &jwt.JWK{
		PublicKey: Alice.Public(),
		KeyID:     "test-kid",
		Algo:      "ES256",
		Use:       "sig",
		Ext:       true,
		KeyOps:    []string{"sign", "verify"},
	}

	vals := jwk.ExportValues()
	if vals["kid"] != "test-kid" {
		t.Error("expected kid in export")
	}
	if vals["alg"] != "ES256" {
		t.Error("expected alg in export")
	}
	if vals["use"] != "sig" {
		t.Error("expected use in export")
	}
	if vals["ext"] != true {
		t.Error("expected ext in export")
	}
	if vals["key_ops"] == nil {
		t.Error("expected key_ops in export")
	}
}

func TestJWKUnmarshalNull(t *testing.T) {
	var jwk jwt.JWK
	err := jwk.UnmarshalJSON([]byte("null"))
	if err != nil {
		t.Errorf("unmarshal null should not error: %s", err)
	}
}

func TestJWKUnmarshalInvalidJSON(t *testing.T) {
	var jwk jwt.JWK
	err := jwk.UnmarshalJSON([]byte("not json"))
	if err == nil {
		t.Error("unmarshal invalid json should error")
	}
}

func TestJWKUnmarshalMissingKty(t *testing.T) {
	var jwk jwt.JWK
	err := jwk.UnmarshalJSON([]byte(`{"kid":"test"}`))
	if err == nil {
		t.Error("unmarshal without kty should error")
	}
}

func TestJWKUnmarshalUnsupportedKty(t *testing.T) {
	var jwk jwt.JWK
	err := jwk.UnmarshalJSON([]byte(`{"kty":"OKP"}`))
	if err == nil {
		t.Error("unmarshal with unsupported kty should error")
	}
}

func TestJWKUnmarshalUnsupportedCurve(t *testing.T) {
	var jwk jwt.JWK
	err := jwk.UnmarshalJSON([]byte(`{"kty":"EC","crv":"P-999","x":"AAAA","y":"BBBB"}`))
	if err == nil {
		t.Error("unsupported curve should error")
	}
}

func TestJWKExportRequiredPublicValuesRSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := &jwt.JWK{PublicKey: &key.PublicKey}

	vals := jwk.ExportRequiredPublicValues()
	if vals["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", vals["kty"])
	}
	if vals["n"] == nil || vals["e"] == nil {
		t.Error("missing n or e")
	}
}

func TestJWKSignAndVerify(t *testing.T) {
	// Sign and verify using JWK directly
	tok := jwt.New(jwt.ES256)
	tok.Payload().Set("iss", "test")

	signed, err := tok.Sign(rand.Reader, Alice)
	if err != nil {
		t.Fatalf("failed to sign with JWK: %s", err)
	}

	tok2, err := jwt.ParseString(signed)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	// verify with JWK (tests the Public() unwrapping)
	err = tok2.Verify(jwt.VerifySignature(Alice))
	if err != nil {
		t.Errorf("failed to verify with JWK: %s", err)
	}
}

func TestJWKRoundtripAllCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %s", err)
			}

			jwk := &jwt.JWK{PrivateKey: key, PublicKey: &key.PublicKey}
			data, err := json.Marshal(jwk)
			if err != nil {
				t.Fatalf("failed to marshal: %s", err)
			}

			var jwk2 jwt.JWK
			err = json.Unmarshal(data, &jwk2)
			if err != nil {
				t.Fatalf("failed to unmarshal: %s", err)
			}
			if jwk2.PrivateKey == nil {
				t.Error("private key should be present after roundtrip")
			}
		})
	}
}
