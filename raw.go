package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type RawToken struct {
	header Header // parsed if needed
	body   Body   // parsed if needed
	values []string
	value  string
}

func ParseString(value string) (*RawToken, error) {
	split := strings.SplitN(value, ".", 3)

	if len(split) < 2 {
		return nil, ErrInvalidToken
	}

	return &RawToken{
		value:  value,
		values: split,
	}, nil
}

func (raw *RawToken) GetAlgo() Algo {
	header, err := raw.Header()
	if err != nil {
		// could not read header, return invalid algo
		return Algo("")
	}

	return header.GetAlgo()
}

func (raw *RawToken) GetKeyId() string {
	header, err := raw.Header()
	if err != nil {
		// could not read header, return empty string
		return ""
	}

	if kid, ok := header["kid"]; ok {
		return kid
	}
	return ""
}

// Header returns the decoded header part of the token and is useful to read
// the kid value for the signature
func (raw *RawToken) Header() (Header, error) {
	if raw.header != nil {
		return raw.header, nil
	}

	str, err := base64.RawURLEncoding.DecodeString(raw.values[0])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(str, &raw.header)
	if err != nil {
		return nil, err
	}

	return raw.header, nil
}

func (raw *RawToken) Body() (Body, error) {
	if raw.body != nil {
		return raw.body, nil
	}

	str, err := base64.RawURLEncoding.DecodeString(raw.values[1])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(str, &raw.body)
	if err != nil {
		return nil, err
	}

	return raw.body, nil
}

func (raw RawToken) writeSignString(w io.Writer) error {
	_, err := w.Write(raw.getSignString())
	return err
}

func (raw RawToken) getSignString() []byte {
	ln := len(raw.values[0]) + len(raw.values[1]) + 1
	return []byte(raw.value[:ln])
}

func (raw *RawToken) Verify(pub interface{}) error {
	if len(raw.values) < 3 {
		return ErrNoSignature
	}
	sign, err := base64.RawURLEncoding.DecodeString(raw.values[3])
	if err != nil {
		return fmt.Errorf("jwt: failed to read signature: %w", err)
	}

	// pub is typically one of *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	algo := raw.GetAlgo()
	hashAlgo := algo.Hash()

	switch algo {
	case HS256: // HMAC
		pk, ok := pub.([]byte)
		if !ok {
			return ErrInvalidSignature
		}
		hash := hmac.New(hashAlgo.New, pk)
		raw.writeSignString(hash)
		if !hmac.Equal(sign, hash.Sum(nil)) {
			return ErrInvalidSignature
		}
		return nil
	case RS256: // RSA
		pk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		hash := hashAlgo.New()
		raw.writeSignString(hash)
		err = rsa.VerifyPKCS1v15(pk, hashAlgo, hash.Sum(nil), sign)
		if err != nil {
			return ErrInvalidSignature
		}
		return nil
	case ES256: // ECDSA
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		hash := hashAlgo.New()
		raw.writeSignString(hash)
		if !ecdsa.VerifyASN1(pk, hash.Sum(nil), sign) {
			return ErrInvalidSignature
		}
		return nil
	case EdDSA:
		pk, ok := pub.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		if !ed25519.Verify(pk, raw.getSignString(), sign) {
			return ErrInvalidSignature
		}
		return nil
	case Algo(""):
		return ErrInvalidToken
	default:
		return ErrInvalidToken
	}
}
