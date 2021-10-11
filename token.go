package jwt

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Token represents a JWT token
type Token struct {
	algo    Algo    // algo value, only used with New() to avoid lookups
	header  Header  // parsed if needed
	payload Payload // parsed if needed
	values  []string
	value   string
}

// New will return a fresh and empty token that can be filled with information
// to be later signed using the Sign method. By default only the "alg" value of
// the header will be set.
func New(alg Algo) *Token {
	return &Token{
		algo:    alg,
		header:  map[string]string{"alg": alg.String()},
		payload: make(Payload),
	}
}

// ParseString will generate a Token object from an encoded string. No
// verification is performed at this point, so it is up to you to call the
// Verify method.
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

// GetAlgo will determine the algorithm in use from the header and return the
// appropriate Algo object, or nil if unknown or no algo is specified.
func (tok *Token) GetAlgo() Algo {
	if tok.algo != nil {
		return tok.algo
	}
	return tok.Header().GetAlgo()
}

// GetKeyId is a short hand for Header().Get("kid").
func (tok *Token) GetKeyId() string {
	return tok.Header().Get("kid")
}

// GetContentType returns the value of "cty" claim in the token's header, ro
// "application/jwt" if not set. It will prepend "application/" to values that
// have no slashes in them as defined in RFC 7515, Section 4.1.10.
func (tok *Token) GetContentType() string {
	cty := tok.Header().Get("cty")
	if cty == "" {
		return "application/jwt"
	}
	if strings.IndexByte(cty, '/') == -1 {
		return "application/" + cty
	}
	return cty
}

// Header returns the decoded header part of the token and is useful to read
// the key id value for the signature.
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

// Payload returns the payload part of the token, which contains the claims. If
// parsing failed, then this function will return nil. Payload methods such as
// Get() and Set() can still be called without causing a panic.
func (tok *Token) Payload() Payload {
	if tok.payload != nil {
		return tok.payload
	}

	str, err := base64.RawURLEncoding.DecodeString(tok.values[1])
	if err != nil {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(str))
	dec.UseNumber()
	err = dec.Decode(&tok.payload)
	if err != nil {
		return nil
	}

	return tok.payload
}

// SetRawPayload sets the raw value of payload to any kind of data that can be
// later signed. This can be used to store non-JSON data in the payload.
func (tok *Token) SetRawPayload(payload []byte, cty string) error {
	tok.payload = nil
	if len(tok.values) < 2 {
		// reset tok.values
		tok.values = []string{"", ""}
	}

	tok.values[1] = base64.RawURLEncoding.EncodeToString(payload)

	if cty != "" {
		return tok.Header().Set("cty", cty)
	}
	return nil
}

// GetRawPayload returns the raw value for the token's payload, or an error if
// it could not be decoded.
func (tok *Token) GetRawPayload() ([]byte, error) {
	if tok.payload != nil {
		return json.Marshal(tok.payload)
	}
	if len(tok.values) < 2 {
		// no payload, return empty json object
		return []byte("{}"), nil
	}
	return base64.RawURLEncoding.DecodeString(tok.values[1])
}

// getSignString is used by VerifySignature to get the part of the string that
// is used to generate a signature. It avoids duplicating memory in order to
// provide better performance.
func (tok Token) getSignString() []byte {
	ln := len(tok.values[0]) + len(tok.values[1]) + 1
	return []byte(tok.value[:ln])
}

// Sign will generate the token and sign it, making it ready for distribution.
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

	if tok.payload == nil {
		if len(tok.values) < 2 {
			values[1] = base64.RawURLEncoding.EncodeToString([]byte("{}")) // empty json payload
		} else {
			values[1] = tok.values[1] // copy existing value as maybe not JSON
		}
	} else {
		jsonVal, err = json.Marshal(tok.Payload())
		if err != nil {
			return "", err
		}
		values[1] = base64.RawURLEncoding.EncodeToString(jsonVal)
	}

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

// Verify will perform the verifications passed as parameter in sequence,
// stopping at the first failure. If all verifications are successful, nil will
// be returned.
func (tok *Token) Verify(opts ...VerifyOption) error {
	// check if we have header & payload
	if tok.Header() == nil {
		return ErrNoHeader
	}
	if tok.Payload() == nil {
		return ErrNoPayload
	}

	for _, opt := range opts {
		if err := opt(tok); err != nil {
			return err
		}
	}
	return nil
}
