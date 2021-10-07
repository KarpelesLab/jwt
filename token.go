package jwt

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Token struct {
	header Header // parsed if needed
	body   Body   // parsed if needed
	values []string
	value  string
}

func ParseString(value string) (*Token, error) {
	split := strings.SplitN(value, ".", 3)

	if len(split) < 2 {
		return nil, ErrInvalidToken
	}

	return &Token{
		value:  value,
		values: split,
	}, nil
}

func (raw *Token) GetAlgo() Algo {
	header, err := raw.Header()
	if err != nil {
		// could not read header, return invalid algo
		return nil
	}

	return header.GetAlgo()
}

func (raw *Token) GetKeyId() string {
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
func (raw *Token) Header() (Header, error) {
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

func (raw *Token) Body() (Body, error) {
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

func (raw Token) writeSignString(w io.Writer) error {
	_, err := w.Write(raw.getSignString())
	return err
}

func (raw Token) getSignString() []byte {
	ln := len(raw.values[0]) + len(raw.values[1]) + 1
	return []byte(raw.value[:ln])
}

func (raw *Token) Sign(priv crypto.PrivateKey) (string, error) {
	algo := raw.GetAlgo()
	if algo == nil {
		return "", ErrInvalidToken
	}

	// build token
	header, err := raw.Header()
	if err != nil {
		return "", err
	}

	body, err := raw.Body()
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}

	// encode to json
	jsonVal, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	buf.WriteString(base64.RawURLEncoding.EncodeToString(jsonVal))

	jsonVal, err = json.Marshal(body)
	if err != nil {
		return "", err
	}

	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(jsonVal))

	sign, err := algo.Sign(buf.Bytes(), priv)
	if err != nil {
		return "", err
	}

	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(sign))

	return buf.String(), nil
}

func (raw *Token) Verify(pub crypto.PublicKey) error {
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
