package jwt

import (
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
		return nil
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
	if algo == nil {
		return ErrInvalidToken // unsupported algo
	}

	return algo.Verify(raw.getSignString(), sign, pub)
}
