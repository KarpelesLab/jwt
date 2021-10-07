package jwt

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type Token struct {
	algo   Algo
	header Header  // parsed if needed
	body   Payload // parsed if needed
	values []string
	value  string
}

func New(alg Algo) *Token {
	return &Token{
		algo:   alg,
		header: map[string]string{"alg": alg.String()},
		body:   make(Payload),
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
	tok.algo = tok.Header().GetAlgo()
	return tok.algo
}

func (tok *Token) GetKeyId() string {
	return tok.Header().Get("kid")
}

// Header returns the decoded header part of the token and is useful to read
// the kid value for the signature
func (tok *Token) Header() Header {
	if tok.header != nil {
		return tok.header
	}

	str, err := base64.RawURLEncoding.DecodeString(tok.values[0])
	if err != nil {
		return nil
	}

	err = json.Unmarshal(str, &tok.header)
	if err != nil {
		return nil
	}

	return tok.header
}

func (tok *Token) Payload() Payload {
	if tok.body != nil {
		return tok.body
	}

	str, err := base64.RawURLEncoding.DecodeString(tok.values[1])
	if err != nil {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(str))
	dec.UseNumber()
	err = dec.Decode(&tok.body)
	if err != nil {
		return nil
	}

	return tok.body
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

	values := make([]string, 2, 3)

	// encode to json
	jsonVal, err := json.Marshal(tok.Header())
	if err != nil {
		return "", err
	}
	values[0] = base64.RawURLEncoding.EncodeToString(jsonVal)

	jsonVal, err = json.Marshal(tok.Payload())
	if err != nil {
		return "", err
	}
	values[1] = base64.RawURLEncoding.EncodeToString(jsonVal)

	// build buf
	buf := &bytes.Buffer{}
	buf.WriteString(values[0])
	buf.WriteByte('.')
	buf.WriteString(values[1])

	// actual signature
	sign, err := algo.Sign(buf.Bytes(), priv)
	if err != nil {
		return "", err
	}
	if sign != nil {
		values = append(values, base64.RawURLEncoding.EncodeToString(sign))

		buf.WriteByte('.')
		buf.WriteString(values[2])
	}

	tok.value = buf.String()
	tok.values = values

	return tok.value, nil
}

func (tok *Token) Verify(pub crypto.PublicKey) error {
	if len(tok.values) < 3 {
		return ErrNoSignature
	}
	sign, err := base64.RawURLEncoding.DecodeString(tok.values[2])
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
