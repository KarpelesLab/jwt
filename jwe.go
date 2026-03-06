package jwt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// KeyAlgo represents a JWE key management algorithm as defined in RFC 7518
// Section 4. It handles wrapping and unwrapping of the Content Encryption Key.
type KeyAlgo interface {
	String() string

	// GenerateCEK generates a Content Encryption Key and wraps it for the
	// recipient. Returns the CEK and the encrypted key. For "dir", the
	// encrypted key will be nil and the provided key is used directly as CEK.
	GenerateCEK(rand io.Reader, keySize int, rcptKey any) (cek, encryptedKey []byte, err error)

	// UnwrapKey recovers the CEK from the encrypted key using the recipient's
	// private key or shared secret.
	UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error)
}

// HeaderKeyAlgo is an optional extension of KeyAlgo for algorithms that need
// access to JWE header parameters during key management. ECDH-ES algorithms
// use this to include the ephemeral public key (epk) in the protected header
// and to read it back during decryption.
type HeaderKeyAlgo interface {
	KeyAlgo

	// GenerateCEKWithHeader generates a CEK and may return additional header
	// parameters to include in the JWE protected header (e.g. "epk").
	// The header parameter contains user-set headers (e.g. "apu", "apv").
	// The encAlg parameter is the "enc" algorithm name for key derivation.
	GenerateCEKWithHeader(rand io.Reader, keySize int, rcptKey any, header Header, encAlg string) (cek, encryptedKey []byte, extraHeaders map[string]any, err error)

	// UnwrapKeyFromHeader recovers the CEK using header information. The
	// header parameter contains the full protected header including
	// algorithm-specific parameters (e.g. "epk", "apu", "apv").
	UnwrapKeyFromHeader(encryptedKey []byte, keySize int, privKey any, header Header, encAlg string) ([]byte, error)
}

// EncAlgo represents a JWE content encryption algorithm as defined in RFC 7518
// Section 5. It provides authenticated encryption of the plaintext.
type EncAlgo interface {
	String() string

	// KeySize returns the required key size in bytes.
	KeySize() int

	// Encrypt performs authenticated encryption. Returns the IV, ciphertext,
	// and authentication tag. The aad parameter is the Additional
	// Authenticated Data (the base64url-encoded protected header).
	Encrypt(rand io.Reader, key, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error)

	// Decrypt performs authenticated decryption, verifying the tag.
	Decrypt(key, iv, ciphertext, tag, aad []byte) ([]byte, error)
}

// EncryptOptions configures the JWE encryption. All fields are optional;
// nil values are auto-detected from the recipient key type.
type EncryptOptions struct {
	// KeyAlgo specifies the key management algorithm. If nil, it is
	// auto-detected from the recipient key type (e.g. *rsa.PublicKey →
	// RSA-OAEP-256, *ecdh.PublicKey → ECDH-ES, []byte → dir).
	KeyAlgo KeyAlgo

	// EncAlgo specifies the content encryption algorithm. If nil, defaults
	// to A256GCM.
	EncAlgo EncAlgo
}

var (
	// Key management algorithms (RFC 7518 Section 4)
	RSA_OAEP     KeyAlgo = rsaOaepKeyAlgo{hash: crypto.SHA1, name: "RSA-OAEP"}.reg()
	RSA_OAEP_256 KeyAlgo = rsaOaepKeyAlgo{hash: crypto.SHA256, name: "RSA-OAEP-256"}.reg()
	Dir          KeyAlgo = dirKeyAlgo{}.reg()
	A128KW       KeyAlgo = aesKwAlgo{keySize: 16}.reg()
	A192KW       KeyAlgo = aesKwAlgo{keySize: 24}.reg()
	A256KW       KeyAlgo = aesKwAlgo{keySize: 32}.reg()

	// Content encryption algorithms (RFC 7518 Section 5)
	A128GCM       EncAlgo = aesGcmEncAlgo{keySize: 16}.reg()
	A192GCM       EncAlgo = aesGcmEncAlgo{keySize: 24}.reg()
	A256GCM       EncAlgo = aesGcmEncAlgo{keySize: 32}.reg()
	A128CBC_HS256 EncAlgo = aesCbcHsEncAlgo{keySize: 32, hash: crypto.SHA256}.reg()
	A192CBC_HS384 EncAlgo = aesCbcHsEncAlgo{keySize: 48, hash: crypto.SHA384}.reg()
	A256CBC_HS512 EncAlgo = aesCbcHsEncAlgo{keySize: 64, hash: crypto.SHA512}.reg()

	keyAlgoMap = make(map[string]KeyAlgo)
	encAlgoMap = make(map[string]EncAlgo)
)

// RegisterKeyAlgo registers a JWE key management algorithm. This is typically
// called during init and no locking is performed.
func RegisterKeyAlgo(obj KeyAlgo) {
	keyAlgoMap[obj.String()] = obj
}

// RegisterEncAlgo registers a JWE content encryption algorithm. This is
// typically called during init and no locking is performed.
func RegisterEncAlgo(obj EncAlgo) {
	encAlgoMap[obj.String()] = obj
}

func parseKeyAlgo(v string) KeyAlgo {
	if a, ok := keyAlgoMap[v]; ok {
		return a
	}
	return nil
}

func parseEncAlgo(v string) EncAlgo {
	if a, ok := encAlgoMap[v]; ok {
		return a
	}
	return nil
}

// GetKeyAlgoForKey returns the default JWE key management algorithm for
// the given key. This is used by Encrypt when no KeyAlgo is specified.
func GetKeyAlgoForKey(key any) (KeyAlgo, error) {
	switch key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		return RSA_OAEP_256, nil
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return ECDH_ES, nil
	case *ecdh.PublicKey, *ecdh.PrivateKey:
		return ECDH_ES, nil
	case *mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768:
		return MLKEM768, nil
	case *mlkem.EncapsulationKey1024, *mlkem.DecapsulationKey1024:
		return MLKEM1024, nil
	case []byte:
		return Dir, nil
	}
	// Try key containers (JWK, etc.)
	if obj, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		if pub := obj.Public(); pub != nil {
			return GetKeyAlgoForKey(pub)
		}
	}
	return nil, fmt.Errorf("jwt: cannot determine encryption algorithm for key type %T", key)
}

// IsEncrypted returns true if the token is a JWE (encrypted) token,
// identified by having 5 dot-separated parts.
func (tok *Token) IsEncrypted() bool {
	return len(tok.values) == 5
}

// Encrypt encrypts the token's payload and returns the JWE compact
// serialization string. The rcptKey is the recipient's public key (for
// RSA-OAEP, ECDH-ES), shared secret (for dir, AES-KW), or encapsulation
// key (for ML-KEM).
//
// If opts is nil, the key management algorithm is auto-detected from the
// key type and A256GCM is used for content encryption. Individual fields
// in opts may also be left nil for auto-detection.
func (tok *Token) Encrypt(rand io.Reader, rcptKey any, opts *EncryptOptions) (string, error) {
	var keyAlg KeyAlgo
	var encAlg EncAlgo

	if opts != nil {
		keyAlg = opts.KeyAlgo
		encAlg = opts.EncAlgo
	}

	// Auto-detect key algorithm from key type
	if keyAlg == nil {
		var err error
		keyAlg, err = GetKeyAlgoForKey(rcptKey)
		if err != nil {
			return "", err
		}
	}

	// Default content encryption algorithm
	if encAlg == nil {
		encAlg = A256GCM
	}

	// Build the protected header
	header := make(Header)
	header["alg"] = keyAlg.String()
	header["enc"] = encAlg.String()
	for k, v := range tok.header {
		if k != "alg" && k != "enc" {
			header[k] = v
		}
	}

	// Get the plaintext
	var plaintext []byte
	var err error
	if tok.payload != nil {
		plaintext, err = json.Marshal(tok.payload)
		if err != nil {
			return "", fmt.Errorf("jwt: failed to encode payload: %w", err)
		}
	} else if len(tok.values) >= 2 {
		plaintext, err = base64.RawURLEncoding.DecodeString(tok.values[1])
		if err != nil {
			return "", fmt.Errorf("jwt: failed to decode raw payload: %w", err)
		}
	} else {
		plaintext = []byte("{}")
	}

	// Generate and wrap the CEK
	var cek, encryptedKey []byte
	if hka, ok := keyAlg.(HeaderKeyAlgo); ok {
		var extraHeaders map[string]any
		cek, encryptedKey, extraHeaders, err = hka.GenerateCEKWithHeader(rand, encAlg.KeySize(), rcptKey, header, encAlg.String())
		for k, v := range extraHeaders {
			header[k] = v
		}
	} else {
		cek, encryptedKey, err = keyAlg.GenerateCEK(rand, encAlg.KeySize(), rcptKey)
	}
	if err != nil {
		return "", fmt.Errorf("jwt: failed to wrap key: %w", err)
	}

	// Serialize header to JSON (this is the AAD)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to encode JWE header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encrypt the plaintext
	iv, ciphertext, tag, err := encAlg.Encrypt(rand, cek, plaintext, []byte(headerB64))
	if err != nil {
		return "", fmt.Errorf("jwt: failed to encrypt: %w", err)
	}

	// Build compact serialization
	values := []string{
		headerB64,
		base64.RawURLEncoding.EncodeToString(encryptedKey),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}

	result := strings.Join(values, ".")
	tok.value = result
	tok.values = values
	tok.header = header

	return result, nil
}

// Decrypt decrypts a JWE token, making the payload accessible via Payload()
// and GetRawPayload(). The privKey is the recipient's private key (for
// RSA-OAEP, ECDH-ES) or shared secret (for dir, AES-KW).
func (tok *Token) Decrypt(privKey any) error {
	if !tok.IsEncrypted() {
		return ErrNotEncrypted
	}

	header := tok.Header()
	if header == nil {
		return ErrNoHeader
	}

	algName := header.Get("alg")
	keyAlg := parseKeyAlgo(algName)
	if keyAlg == nil {
		return fmt.Errorf("%w: %s", ErrUnknownAlg, algName)
	}

	encName := header.Get("enc")
	encAlg := parseEncAlgo(encName)
	if encAlg == nil {
		return fmt.Errorf("%w: %s", ErrUnknownEnc, encName)
	}

	// Decode the JWE parts
	encryptedKey, err := base64.RawURLEncoding.DecodeString(tok.values[1])
	if err != nil {
		return fmt.Errorf("jwt: failed to decode encrypted key: %w", err)
	}
	iv, err := base64.RawURLEncoding.DecodeString(tok.values[2])
	if err != nil {
		return fmt.Errorf("jwt: failed to decode IV: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(tok.values[3])
	if err != nil {
		return fmt.Errorf("jwt: failed to decode ciphertext: %w", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(tok.values[4])
	if err != nil {
		return fmt.Errorf("jwt: failed to decode authentication tag: %w", err)
	}

	// Unwrap the CEK
	var cek []byte
	if hka, ok := keyAlg.(HeaderKeyAlgo); ok {
		cek, err = hka.UnwrapKeyFromHeader(encryptedKey, encAlg.KeySize(), privKey, header, encName)
	} else {
		cek, err = keyAlg.UnwrapKey(encryptedKey, encAlg.KeySize(), privKey)
	}
	if err != nil {
		return fmt.Errorf("jwt: failed to unwrap key: %w", err)
	}

	// Decrypt
	aad := []byte(tok.values[0])
	plaintext, err := encAlg.Decrypt(cek, iv, ciphertext, tag, aad)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Store the decrypted payload so Payload() and GetRawPayload() work
	tok.values = []string{
		tok.values[0],
		base64.RawURLEncoding.EncodeToString(plaintext),
	}
	tok.payload = nil

	return nil
}
