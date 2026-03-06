package jwt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

// ecdhEsAlgo implements HeaderKeyAlgo for ECDH-ES key agreement
// as specified in RFC 7518 Section 4.6.
type ecdhEsAlgo struct {
	name        string
	wrapKeySize int // 0 for ECDH-ES (direct), 16/24/32 for ECDH-ES+A*KW
}

var (
	// ECDH-ES key agreement algorithms (RFC 7518 Section 4.6)
	ECDH_ES        KeyAlgo = ecdhEsAlgo{name: "ECDH-ES"}.reg()
	ECDH_ES_A128KW KeyAlgo = ecdhEsAlgo{name: "ECDH-ES+A128KW", wrapKeySize: 16}.reg()
	ECDH_ES_A192KW KeyAlgo = ecdhEsAlgo{name: "ECDH-ES+A192KW", wrapKeySize: 24}.reg()
	ECDH_ES_A256KW KeyAlgo = ecdhEsAlgo{name: "ECDH-ES+A256KW", wrapKeySize: 32}.reg()
)

func (a ecdhEsAlgo) String() string { return a.name }

// GenerateCEK satisfies the KeyAlgo interface but is not used directly for
// ECDH-ES algorithms since they require header access. The Encrypt method
// detects HeaderKeyAlgo and calls GenerateCEKWithHeader instead.
func (a ecdhEsAlgo) GenerateCEK(rand io.Reader, keySize int, rcptKey any) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("jwt: %s requires header context", a.name)
}

// UnwrapKey satisfies the KeyAlgo interface but is not used directly.
func (a ecdhEsAlgo) UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error) {
	return nil, fmt.Errorf("jwt: %s requires header context", a.name)
}

// GenerateCEKWithHeader performs ECDH key agreement with an ephemeral key pair
// and returns the CEK along with extra header parameters (epk).
func (a ecdhEsAlgo) GenerateCEKWithHeader(rng io.Reader, keySize int, rcptKey any, header Header, encAlg string) ([]byte, []byte, map[string]any, error) {
	pub, err := toECDHPublicKey(rcptKey)
	if err != nil {
		return nil, nil, nil, err
	}

	curve, curveName, err := ecdhCurveFromPublicKey(pub)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate ephemeral key pair on the same curve
	ephemeral, err := curve.GenerateKey(rng)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH
	z, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: ECDH key agreement failed: %w", err)
	}

	// Read apu/apv from header (user may have set these)
	var apu, apv []byte
	if apuStr := header.Get("apu"); apuStr != "" {
		apu, _ = base64.RawURLEncoding.DecodeString(apuStr)
	}
	if apvStr := header.Get("apv"); apvStr != "" {
		apv, _ = base64.RawURLEncoding.DecodeString(apvStr)
	}

	// Determine algorithm ID and derived key size for Concat KDF
	var algID string
	var derivedKeySize int
	if a.wrapKeySize == 0 {
		// ECDH-ES: derived key IS the CEK
		algID = encAlg
		derivedKeySize = keySize
	} else {
		// ECDH-ES+A*KW: derived key is the KEK for AES-KW
		algID = a.name
		derivedKeySize = a.wrapKeySize
	}

	derivedKey, err := concatKDF(z, derivedKeySize, []byte(algID), apu, apv)
	if err != nil {
		return nil, nil, nil, err
	}

	extraHeaders := map[string]any{
		"epk": ecdhPublicKeyToJWK(ephemeral.PublicKey(), curveName),
	}

	if a.wrapKeySize == 0 {
		// ECDH-ES: derived key is the CEK, no encrypted key
		return derivedKey, nil, extraHeaders, nil
	}

	// ECDH-ES+A*KW: generate random CEK and wrap with derived KEK
	cek := make([]byte, keySize)
	if _, err := io.ReadFull(rng, cek); err != nil {
		return nil, nil, nil, err
	}

	encryptedKey, err := aesKeyWrap(derivedKey, cek)
	if err != nil {
		return nil, nil, nil, err
	}

	return cek, encryptedKey, extraHeaders, nil
}

// UnwrapKeyFromHeader recovers the CEK by performing ECDH with the ephemeral
// public key from the header.
func (a ecdhEsAlgo) UnwrapKeyFromHeader(encryptedKey []byte, keySize int, privKey any, header Header, encAlg string) ([]byte, error) {
	// Get the ephemeral public key from the header
	epkVal, ok := header["epk"]
	if !ok {
		return nil, fmt.Errorf("jwt: missing epk header parameter")
	}
	epkMap, ok := epkVal.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jwt: invalid epk header parameter")
	}

	ephemeralPub, err := jwkToECDHPublicKey(epkMap)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to parse epk: %w", err)
	}

	priv, err := toECDHPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	// Perform ECDH
	z, err := priv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("jwt: ECDH key agreement failed: %w", err)
	}

	// Read apu/apv from header
	var apu, apv []byte
	if apuStr := header.Get("apu"); apuStr != "" {
		apu, _ = base64.RawURLEncoding.DecodeString(apuStr)
	}
	if apvStr := header.Get("apv"); apvStr != "" {
		apv, _ = base64.RawURLEncoding.DecodeString(apvStr)
	}

	// Determine algorithm ID and derived key size
	var algID string
	var derivedKeySize int
	if a.wrapKeySize == 0 {
		algID = encAlg
		derivedKeySize = keySize
	} else {
		algID = a.name
		derivedKeySize = a.wrapKeySize
	}

	derivedKey, err := concatKDF(z, derivedKeySize, []byte(algID), apu, apv)
	if err != nil {
		return nil, err
	}

	if a.wrapKeySize == 0 {
		// ECDH-ES: derived key is the CEK directly
		if len(encryptedKey) != 0 {
			return nil, fmt.Errorf("jwt: encrypted key must be empty for ECDH-ES")
		}
		return derivedKey, nil
	}

	// ECDH-ES+A*KW: unwrap CEK with derived KEK
	return aesKeyUnwrap(derivedKey, encryptedKey)
}

func (a ecdhEsAlgo) reg() KeyAlgo {
	RegisterKeyAlgo(a)
	return a
}

// concatKDF implements the Concat KDF as specified in RFC 7518 Section 4.6.2
// (NIST SP 800-56A). It uses SHA-256 as the hash function.
func concatKDF(z []byte, keyDataLen int, algID, apu, apv []byte) ([]byte, error) {
	hashLen := 32 // SHA-256 output size
	reps := (keyDataLen + hashLen - 1) / hashLen

	// Build OtherInfo per RFC 7518 Section 4.6.2
	otherInfo := new(bytes.Buffer)
	// AlgorithmID: length-prefixed
	binary.Write(otherInfo, binary.BigEndian, uint32(len(algID)))
	otherInfo.Write(algID)
	// PartyUInfo: length-prefixed
	binary.Write(otherInfo, binary.BigEndian, uint32(len(apu)))
	if len(apu) > 0 {
		otherInfo.Write(apu)
	}
	// PartyVInfo: length-prefixed
	binary.Write(otherInfo, binary.BigEndian, uint32(len(apv)))
	if len(apv) > 0 {
		otherInfo.Write(apv)
	}
	// SuppPubInfo: keydatalen in bits
	binary.Write(otherInfo, binary.BigEndian, uint32(keyDataLen*8))

	var derivedKey []byte
	for counter := 1; counter <= reps; counter++ {
		h := sha256.New()
		binary.Write(h, binary.BigEndian, uint32(counter))
		h.Write(z)
		h.Write(otherInfo.Bytes())
		derivedKey = append(derivedKey, h.Sum(nil)...)
	}

	return derivedKey[:keyDataLen], nil
}

// toECDHPublicKey converts various key types to *ecdh.PublicKey.
func toECDHPublicKey(key any) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdh.PrivateKey:
		return k.PublicKey(), nil
	case *ecdsa.PublicKey:
		return k.ECDH()
	case *ecdsa.PrivateKey:
		return k.PublicKey.ECDH()
	default:
		return nil, fmt.Errorf("%w: expected ECDH or ECDSA key, got %T", ErrInvalidPublicKey, key)
	}
}

// toECDHPrivateKey converts various key types to *ecdh.PrivateKey.
func toECDHPrivateKey(key any) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("%w: expected ECDH or ECDSA private key, got %T", ErrInvalidSignKey, key)
	}
}

// ecdhCurveFromPublicKey determines the ECDH curve from a public key's byte length.
func ecdhCurveFromPublicKey(key *ecdh.PublicKey) (ecdh.Curve, string, error) {
	switch len(key.Bytes()) {
	case 32:
		return ecdh.X25519(), "X25519", nil
	case 65:
		return ecdh.P256(), "P-256", nil
	case 97:
		return ecdh.P384(), "P-384", nil
	case 133:
		return ecdh.P521(), "P-521", nil
	default:
		return nil, "", fmt.Errorf("jwt: unsupported ECDH key size: %d bytes", len(key.Bytes()))
	}
}

// ecdhPublicKeyToJWK serializes an ECDH public key as a JWK map.
func ecdhPublicKeyToJWK(key *ecdh.PublicKey, curveName string) map[string]any {
	raw := key.Bytes()

	if curveName == "X25519" {
		return map[string]any{
			"kty": "OKP",
			"crv": "X25519",
			"x":   base64.RawURLEncoding.EncodeToString(raw),
		}
	}

	// EC curves: uncompressed point 0x04 || x || y
	coordSize := (len(raw) - 1) / 2
	x := raw[1 : 1+coordSize]
	y := raw[1+coordSize:]

	return map[string]any{
		"kty": "EC",
		"crv": curveName,
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

// jwkToECDHPublicKey parses a JWK map into an ECDH public key.
func jwkToECDHPublicKey(jwk map[string]any) (*ecdh.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	if kty == "OKP" && crv == "X25519" {
		xStr, _ := jwk["x"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("jwt: failed to decode X25519 key: %w", err)
		}
		return ecdh.X25519().NewPublicKey(xBytes)
	}

	if kty != "EC" {
		return nil, fmt.Errorf("jwt: unsupported epk kty: %s", kty)
	}

	curve, err := ecdhCurveFromName(crv)
	if err != nil {
		return nil, err
	}

	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to decode epk x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to decode epk y coordinate: %w", err)
	}

	// Build uncompressed point: 0x04 || x || y
	point := make([]byte, 1+len(xBytes)+len(yBytes))
	point[0] = 0x04
	copy(point[1:], xBytes)
	copy(point[1+len(xBytes):], yBytes)

	return curve.NewPublicKey(point)
}

// ecdhCurveFromName returns the ECDH curve for a JWK curve name.
func ecdhCurveFromName(name string) (ecdh.Curve, error) {
	switch name {
	case "P-256":
		return ecdh.P256(), nil
	case "P-384":
		return ecdh.P384(), nil
	case "P-521":
		return ecdh.P521(), nil
	case "X25519":
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("jwt: unsupported ECDH curve: %s", name)
	}
}
