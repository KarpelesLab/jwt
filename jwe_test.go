package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"strings"
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestJWE_RSAOAEP256_A256GCM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("sub", "user123")
	tok.Payload().Set("iss", "test")

	// nil opts → auto-detects RSA-OAEP-256 + A256GCM
	encrypted, err := tok.Encrypt(rand.Reader, &key.PublicKey, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	// JWE has 5 parts
	if parts := strings.Split(encrypted, "."); len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	// Parse and decrypt
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
	if tok2.IsEncrypted() {
		t.Error("token should not appear encrypted after decryption")
	}

	if tok2.Payload().GetString("sub") != "user123" {
		t.Errorf("expected sub=user123, got %s", tok2.Payload().GetString("sub"))
	}
	if tok2.Payload().GetString("iss") != "test" {
		t.Errorf("expected iss=test, got %s", tok2.Payload().GetString("iss"))
	}

	// Verify auto-detected algo
	if tok2.Header().Get("alg") != "RSA-OAEP-256" {
		t.Errorf("expected alg=RSA-OAEP-256, got %s", tok2.Header().Get("alg"))
	}
}

func TestJWE_RSAOAEP_A128GCM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("data", "hello")

	encrypted, err := tok.Encrypt(rand.Reader, &key.PublicKey, &jwt.EncryptOptions{KeyAlgo: jwt.RSA_OAEP, EncAlgo: jwt.A128GCM})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Decrypt(key)
	if err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}

	if tok2.Payload().GetString("data") != "hello" {
		t.Error("payload mismatch")
	}
}

func TestJWE_Dir_A256GCM(t *testing.T) {
	key := make([]byte, 32) // 256-bit key for A256GCM
	rand.Read(key)

	tok := jwt.New()
	tok.Payload().Set("msg", "secret")

	// nil opts → auto-detects dir + A256GCM
	encrypted, err := tok.Encrypt(rand.Reader, key, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	// For dir, the encrypted key part should be empty
	parts := strings.Split(encrypted, ".")
	if parts[1] != "" {
		t.Error("encrypted key should be empty for dir")
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}

	err = tok2.Decrypt(key)
	if err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}

	if tok2.Payload().GetString("msg") != "secret" {
		t.Error("payload mismatch")
	}
}

func TestJWE_Dir_A128GCM(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	tok := jwt.New()
	tok.Payload().Set("x", "y")

	encrypted, err := tok.Encrypt(rand.Reader, key, &jwt.EncryptOptions{EncAlgo: jwt.A128GCM})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("x") != "y" {
		t.Error("payload mismatch")
	}
}

func TestJWE_A128KW_A128GCM(t *testing.T) {
	kek := make([]byte, 16)
	rand.Read(kek)

	tok := jwt.New()
	tok.Payload().Set("wrapped", true)

	encrypted, err := tok.Encrypt(rand.Reader, kek, &jwt.EncryptOptions{KeyAlgo: jwt.A128KW, EncAlgo: jwt.A128GCM})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(kek); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().Get("wrapped") != true {
		t.Error("payload mismatch")
	}
}

func TestJWE_A256KW_A256GCM(t *testing.T) {
	kek := make([]byte, 32)
	rand.Read(kek)

	tok := jwt.New()
	tok.Payload().Set("val", "test")

	encrypted, err := tok.Encrypt(rand.Reader, kek, &jwt.EncryptOptions{KeyAlgo: jwt.A256KW})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(kek); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("val") != "test" {
		t.Error("payload mismatch")
	}
}

func TestJWE_RSAOAEP256_A128CBC_HS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	tok := jwt.New()
	tok.Payload().Set("sub", "cbc-test")

	encrypted, err := tok.Encrypt(rand.Reader, &key.PublicKey, &jwt.EncryptOptions{EncAlgo: jwt.A128CBC_HS256})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("sub") != "cbc-test" {
		t.Error("payload mismatch")
	}
}

func TestJWE_Dir_A256CBC_HS512(t *testing.T) {
	key := make([]byte, 64) // A256CBC-HS512 needs 64 bytes
	rand.Read(key)

	tok := jwt.New()
	tok.Payload().Set("data", "cbc512")

	encrypted, err := tok.Encrypt(rand.Reader, key, &jwt.EncryptOptions{EncAlgo: jwt.A256CBC_HS512})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("data") != "cbc512" {
		t.Error("payload mismatch")
	}
}

func TestJWE_A192KW_A192CBC_HS384(t *testing.T) {
	kek := make([]byte, 24)
	rand.Read(kek)

	tok := jwt.New()
	tok.Payload().Set("n", "192")

	encrypted, err := tok.Encrypt(rand.Reader, kek, &jwt.EncryptOptions{KeyAlgo: jwt.A192KW, EncAlgo: jwt.A192CBC_HS384})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, err := jwt.ParseString(encrypted)
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	if err := tok2.Decrypt(kek); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("n") != "192" {
		t.Error("payload mismatch")
	}
}

func TestJWE_DecryptWrongKey(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	tok := jwt.New()
	tok.Payload().Set("secret", "data")

	encrypted, err := tok.Encrypt(rand.Reader, &key1.PublicKey, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	err = tok2.Decrypt(key2)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestJWE_DecryptWrongSymmetricKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	tok := jwt.New()
	tok.Payload().Set("x", "y")

	encrypted, _ := tok.Encrypt(rand.Reader, key1, nil)

	tok2, _ := jwt.ParseString(encrypted)
	err := tok2.Decrypt(key2)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestJWE_DecryptNotEncrypted(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("x", "y")

	err := tok.Decrypt([]byte("key"))
	if err == nil {
		t.Error("should fail on non-encrypted token")
	}
}

func TestJWE_HeaderPreserved(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tok := jwt.New()
	tok.Header().Set("kid", "mykey")
	tok.Payload().Set("x", "y")

	encrypted, err := tok.Encrypt(rand.Reader, key, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if tok2.Header().Get("kid") != "mykey" {
		t.Error("kid header should be preserved")
	}
	if tok2.Header().Get("enc") != "A256GCM" {
		t.Error("enc header should be set")
	}
	if tok2.Header().Get("alg") != "dir" {
		t.Error("alg header should be set")
	}
}

func TestJWE_RawPayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tok := jwt.New()
	tok.SetRawPayload([]byte("raw binary data"), "octet-stream")

	encrypted, err := tok.Encrypt(rand.Reader, key, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}

	raw, err := tok2.GetRawPayload()
	if err != nil {
		t.Fatalf("GetRawPayload failed: %s", err)
	}
	if string(raw) != "raw binary data" {
		t.Errorf("expected 'raw binary data', got '%s'", string(raw))
	}
}

func TestJWE_RSAWithJWK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := &jwt.JWK{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}

	tok := jwt.New()
	tok.Payload().Set("via", "jwk")

	// Auto-detects RSA-OAEP-256 via JWK's Public() method
	encrypted, err := tok.Encrypt(rand.Reader, jwk, nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	// Decrypt with JWK (uses crypto.Decrypter interface)
	tok2, _ := jwt.ParseString(encrypted)
	err = tok2.Decrypt(jwk)
	if err != nil {
		t.Fatalf("failed to decrypt with JWK: %s", err)
	}
	if tok2.Payload().GetString("via") != "jwk" {
		t.Error("payload mismatch")
	}
}

func TestJWE_InvalidKeyType(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("x", "y")

	// Wrong key type for RSA-OAEP
	_, err := tok.Encrypt(rand.Reader, []byte("not-rsa"), &jwt.EncryptOptions{KeyAlgo: jwt.RSA_OAEP_256})
	if err == nil {
		t.Error("should fail with wrong key type")
	}

	// Wrong key type for dir
	_, err = tok.Encrypt(rand.Reader, "not-bytes", &jwt.EncryptOptions{KeyAlgo: jwt.Dir})
	if err == nil {
		t.Error("should fail with wrong key type for dir")
	}

	// Wrong key size for dir
	_, err = tok.Encrypt(rand.Reader, []byte("short"), nil)
	if err == nil {
		t.Error("should fail with wrong key size for dir")
	}

	// Wrong key type for AES-KW
	_, err = tok.Encrypt(rand.Reader, "not-bytes", &jwt.EncryptOptions{KeyAlgo: jwt.A128KW, EncAlgo: jwt.A128GCM})
	if err == nil {
		t.Error("should fail with wrong key type for AES-KW")
	}

	// Wrong key size for AES-KW
	_, err = tok.Encrypt(rand.Reader, []byte("short"), &jwt.EncryptOptions{KeyAlgo: jwt.A128KW, EncAlgo: jwt.A128GCM})
	if err == nil {
		t.Error("should fail with wrong key size for AES-KW")
	}
}

func TestJWE_A192GCM(t *testing.T) {
	key := make([]byte, 24)
	rand.Read(key)

	tok := jwt.New()
	tok.Payload().Set("v", "192gcm")

	encrypted, err := tok.Encrypt(rand.Reader, key, &jwt.EncryptOptions{EncAlgo: jwt.A192GCM})
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	tok2, _ := jwt.ParseString(encrypted)
	if err := tok2.Decrypt(key); err != nil {
		t.Fatalf("failed to decrypt: %s", err)
	}
	if tok2.Payload().GetString("v") != "192gcm" {
		t.Error("payload mismatch")
	}
}

func TestJWE_AutoDetect(t *testing.T) {
	// RSA key → RSA-OAEP-256
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	algo, err := jwt.GetKeyAlgoForKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to detect RSA algo: %s", err)
	}
	if algo.String() != "RSA-OAEP-256" {
		t.Errorf("expected RSA-OAEP-256, got %s", algo.String())
	}

	// []byte → dir
	algo, err = jwt.GetKeyAlgoForKey([]byte("key"))
	if err != nil {
		t.Fatalf("failed to detect dir algo: %s", err)
	}
	if algo.String() != "dir" {
		t.Errorf("expected dir, got %s", algo.String())
	}

	// Unknown type → error
	_, err = jwt.GetKeyAlgoForKey(42)
	if err == nil {
		t.Error("should fail for unknown key type")
	}
}
