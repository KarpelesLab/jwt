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
	algo   Algo
	header Header // parsed if needed
	body   Body   // parsed if needed
	values []string
	value  string
}

func New(alg Algo) *Token {
	return &Token{
		algo:   alg,
		header: map[string]string{"alg": alg.String()},
		body:   make(Body),
	}
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

func (tok *Token) GetAlgo() Algo {
	if tok.algo != nil {
		return tok.algo
	}
	header, err := tok.Header()
	if err != nil {
		// could not read header, return invalid algo
		return nil
	}

	tok.algo = header.GetAlgo()
	return tok.algo
}

func (tok *Token) GetKeyId() string {
	header, err := tok.Header()
	if err != nil {
		// could not read header, return empty string
		return ""
	}

	if kid, ok := header["kid"]; ok {
		return kid
	}
	return ""
}

func (tok *Token) SetHeader(key, value string) error {
	header, err := tok.Header()
	if err != nil {
		return err
	}
	header[key] = value
	return nil
}

func (tok *Token) Set(key string, value interface{}) error {
	body, err := tok.Body()
	if err != nil {
		return err
	}
	body[key] = value
	return nil
}

// Header returns the decoded header part of the token and is useful to read
// the kid value for the signature
func (tok *Token) Header() (Header, error) {
	if tok.header != nil {
		return tok.header, nil
	}

	str, err := base64.RawURLEncoding.DecodeString(tok.values[0])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(str, &tok.header)
	if err != nil {
		return nil, err
	}

	return tok.header, nil
}

func (tok *Token) Body() (Body, error) {
	if tok.body != nil {
		return tok.body, nil
	}

	str, err := base64.RawURLEncoding.DecodeString(tok.values[1])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(str, &tok.body)
	if err != nil {
		return nil, err
	}

	return tok.body, nil
}

func (tok Token) writeSignString(w io.Writer) error {
	_, err := w.Write(tok.getSignString())
	return err
}

func (tok Token) getSignString() []byte {
	ln := len(tok.values[0]) + len(tok.values[1]) + 1
	return []byte(tok.value[:ln])
}

func (tok *Token) Sign(priv crypto.PrivateKey) (string, error) {
	algo := tok.GetAlgo()
	if algo == nil {
		return "", ErrInvalidToken
	}

	// build token
	header, err := tok.Header()
	if err != nil {
		return "", err
	}

	body, err := tok.Body()
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

func (tok *Token) Verify(pub crypto.PublicKey) error {
	if len(tok.values) < 3 {
		return ErrNoSignature
	}
	sign, err := base64.RawURLEncoding.DecodeString(tok.values[3])
	if err != nil {
		return fmt.Errorf("jwt: failed to read signature: %w", err)
	}

	// pub is typically one of *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	algo := tok.GetAlgo()
	if algo == nil {
		return ErrInvalidToken // unsupported algo
	}

	return algo.Verify(tok.getSignString(), sign, pub)
}
