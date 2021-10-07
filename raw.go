package jwt

import (
	"encoding/base64"
	"encoding/json"
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
