package jwt_test

import (
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestMLKEM768_A256GCM(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("msg", "quantum-safe")

	encrypted, err := tok.Encrypt(rand.Reader, dk.EncapsulationKey(), jwt.MLKEM768, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if !tok2.IsEncrypted() {
		t.Fatal("token should be encrypted")
	}

	err = tok2.Decrypt(dk)
	if err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}

	if tok2.Payload().GetString("msg") != "quantum-safe" {
		t.Error("payload mismatch")
	}
}

func TestMLKEM768_A128CBC_HS256(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("enc", "cbc")

	encrypted, err := tok.Encrypt(rand.Reader, dk.EncapsulationKey(), jwt.MLKEM768, jwt.A128CBC_HS256)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(dk); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("enc") != "cbc" {
		t.Error("payload mismatch")
	}
}

func TestMLKEM1024_A256GCM(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("level", "1024")

	encrypted, err := tok.Encrypt(rand.Reader, dk.EncapsulationKey(), jwt.MLKEM1024, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(dk); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("level") != "1024" {
		t.Error("payload mismatch")
	}
}

func TestMLKEM768_EncapsulateFromDecapKey(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	// Pass DecapsulationKey directly — should extract EncapsulationKey
	tok := jwt.New()
	tok.Payload().Set("x", "y")

	encrypted, err := tok.Encrypt(rand.Reader, dk, jwt.MLKEM768, jwt.A256GCM)
	if err != nil {
		t.Fatalf("failed to encrypt with decap key: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(dk); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("x") != "y" {
		t.Error("payload mismatch")
	}
}

func TestMLKEM768_WrongKey(t *testing.T) {
	dk1, _ := mlkem.GenerateKey768()
	dk2, _ := mlkem.GenerateKey768()

	tok := jwt.New()
	tok.Payload().Set("secret", "data")

	encrypted, _ := tok.Encrypt(rand.Reader, dk1.EncapsulationKey(), jwt.MLKEM768, jwt.A256GCM)

	tok2, _ := jwt.ParseString(encrypted)
	err := tok2.Decrypt(dk2)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestMLKEM_InvalidKeyType(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("x", "y")

	_, err := tok.Encrypt(rand.Reader, []byte("wrong"), jwt.MLKEM768, jwt.A256GCM)
	if err == nil {
		t.Error("should fail with wrong key type")
	}

	_, err = tok.Encrypt(rand.Reader, []byte("wrong"), jwt.MLKEM1024, jwt.A256GCM)
	if err == nil {
		t.Error("should fail with wrong key type for 1024")
	}
}

func TestMLKEM768_A256CBC_HS512(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	// Test with larger key size (64 bytes) requiring HKDF derivation
	tok := jwt.New()
	tok.Payload().Set("big", "key")

	encrypted, err := tok.Encrypt(rand.Reader, dk.EncapsulationKey(), jwt.MLKEM768, jwt.A256CBC_HS512)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(dk); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("big") != "key" {
		t.Error("payload mismatch")
	}
}

func TestMLKEM1024_DecryptWrongLevel(t *testing.T) {
	dk768, _ := mlkem.GenerateKey768()
	dk1024, _ := mlkem.GenerateKey1024()

	tok := jwt.New()
	tok.Payload().Set("x", "y")

	encrypted, _ := tok.Encrypt(rand.Reader, dk1024.EncapsulationKey(), jwt.MLKEM1024, jwt.A256GCM)

	// Try to decrypt ML-KEM-1024 token with 768 key — wrong type
	tok2, _ := jwt.ParseString(encrypted)
	err := tok2.Decrypt(dk768)
	if err == nil {
		t.Error("should fail with wrong key level")
	}
}
