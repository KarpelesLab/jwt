package jwt_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestECDHES_P256_A128GCM(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("sub", "ecdh-user")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A128GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	// JWE has 5 parts
	parts := strings.Split(encrypted, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	// For ECDH-ES, encrypted key must be empty
	if parts[1] != "" {
		t.Error("encrypted key should be empty for ECDH-ES")
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if !tok2.IsEncrypted() {
		t.Fatal("token should be encrypted")
	}

	err = tok2.Decrypt(key)
	if err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}

	if tok2.Payload().GetString("sub") != "ecdh-user" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_P384_A256GCM(t *testing.T) {
	key, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("curve", "P-384")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("curve") != "P-384" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_P521_A256GCM(t *testing.T) {
	key, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("curve", "P-521")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("curve") != "P-521" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_X25519_A256GCM(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("curve", "X25519")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("curve") != "X25519" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_A128KW_A256GCM(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("mode", "keywrap")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES_A128KW, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	// For ECDH-ES+A128KW, encrypted key should NOT be empty
	parts := strings.Split(encrypted, ".")
	if parts[1] == "" {
		t.Error("encrypted key should not be empty for ECDH-ES+A128KW")
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("mode") != "keywrap" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_A256KW_A256GCM(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("wrap", "256")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES_A256KW, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("wrap") != "256" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_A192KW_A192CBC_HS384(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("enc", "cbc")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES_A192KW, jwt.A192CBC_HS384)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("enc") != "cbc" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_WithECDSAKey(t *testing.T) {
	// Test that ECDSA keys are automatically converted to ECDH
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("key", "ecdsa")

	// Encrypt with ECDSA public key
	encrypted, err := tok.Encrypt(rand.Reader, &ecdsaKey.PublicKey, jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt with ECDSA key: %s", err)
	}

	// Decrypt with ECDSA private key
	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(ecdsaKey); err != nil {
		t.Fatalf("failed to decrypt with ECDSA key: %s", err)
	}
	if tok2.Payload().GetString("key") != "ecdsa" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_WithApuApv(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("with", "parties")
	tok.Header().Set("apu", base64.RawURLEncoding.EncodeToString([]byte("Alice")))
	tok.Header().Set("apv", base64.RawURLEncoding.EncodeToString([]byte("Bob")))

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("with") != "parties" {
		t.Error("payload mismatch")
	}
}

func TestECDHES_WrongKey(t *testing.T) {
	key1, _ := ecdh.P256().GenerateKey(rand.Reader)
	key2, _ := ecdh.P256().GenerateKey(rand.Reader)

	tok := jwt.New()
	tok.Payload().Set("secret", "data")

	encrypted, _ := tok.Encrypt(rand.Reader, key1.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)

	tok2, _ := jwt.ParseString(encrypted)
	err := tok2.Decrypt(key2)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestECDHES_InvalidKeyType(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("x", "y")

	_, err := tok.Encrypt(rand.Reader, []byte("not-a-key"), jwt.ECDH_ES, jwt.A256GCM)
	if err == nil {
		t.Error("should fail with invalid key type")
	}
}

func TestECDHES_HeaderPreserved(t *testing.T) {
	key, _ := ecdh.P256().GenerateKey(rand.Reader)

	tok := jwt.New()
	tok.Header().Set("kid", "ec-key-1")
	tok.Payload().Set("x", "y")

	encrypted, err := tok.Encrypt(rand.Reader, key.PublicKey(), jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if tok2.Header().Get("alg") != "ECDH-ES" {
		t.Error("alg header mismatch")
	}
	if tok2.Header().Get("enc") != "A256GCM" {
		t.Error("enc header mismatch")
	}
	if tok2.Header().Get("kid") != "ec-key-1" {
		t.Error("kid header should be preserved")
	}
	// epk should be present
	if !tok2.Header().Has("epk") {
		t.Error("epk header should be present")
	}
}

func TestECDHES_EncryptFromPrivateKey(t *testing.T) {
	// When a private key is passed for encryption, the public key should
	// be extracted automatically
	key, _ := ecdh.P256().GenerateKey(rand.Reader)

	tok := jwt.New()
	tok.Payload().Set("from", "privkey")

	encrypted, err := tok.Encrypt(rand.Reader, key, jwt.ECDH_ES, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt from private key: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("from") != "privkey" {
		t.Error("payload mismatch")
	}
}
