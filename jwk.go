package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

type JWK struct {
	PrivateKey crypto.PrivateKey `json:"-"`
	PublicKey  crypto.PublicKey  `json:"-"`
	KeyID      string            `json:"kid,omitempty"`
	Algo       string            `json:"alg,omitempty"` // RSA-OAEP-256
	Use        string            `json:"use,omitempty"`
	Ext        bool              `json:"ext,omitempty"`
	KeyOps     []string          `json:"key_ops,omitempty"`
}

func (jwk *JWK) String() string {
	if jwk.PrivateKey != nil {
		return fmt.Sprintf("JWK[%T]", jwk.PrivateKey)
	}
	return fmt.Sprintf("JWK[%T]", jwk.PublicKey)
}

func (jwk *JWK) Public() crypto.PublicKey {
	if jwk.PrivateKey != nil {
		if v, ok := jwk.PrivateKey.(interface{ Public() crypto.PublicKey }); ok {
			return v.Public()
		}
	}
	return jwk.PublicKey
}

func (jwk *JWK) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if jwk.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}
	if sig, ok := jwk.PrivateKey.(crypto.Signer); ok {
		return sig.Sign(rand, digest, opts)
	}
	return nil, ErrNoPrivateKey
}

func (jwk *JWK) ThumbprintHex(method crypto.Hash) string {
	v, err := jwk.Thumbprint(method)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(v)
}

func (jwk *JWK) Thumbprint(method crypto.Hash) ([]byte, error) {
	// compute thumbprint
	// https://www.rfc-editor.org/rfc/rfc7638

	// we need to export in json format in alphabetical order. Golang does that for us :)
	v, err := json.Marshal(jwk.ExportRequiredPublicValues())
	if err != nil {
		return nil, err
	}

	h := method.New()
	h.Write(v)
	return h.Sum(nil), nil
}

func (jwk *JWK) UnmarshalJSON(v []byte) error {
	if bytes.Equal(v, []byte("null")) {
		// no-op
		return nil
	}

	var tmp map[string]any

	err := json.Unmarshal(v, &tmp)
	if err != nil {
		return err
	}

	return jwk.ApplyValues(tmp)
}

func (jwk *JWK) ApplyValues(values map[string]any) error {
	kty, ok := values["kty"]
	if !ok {
		return fmt.Errorf("JWK object requires kty attribute")
	}

	switch kty {
	case "RSA":
		// e, n, and d if private key

		// e=AQAB = 0x010001 = 65537
		eB, err := jwkBase64ToBigInt(values["e"])
		if err != nil {
			return fmt.Errorf("while reading e: %w", err)
		}
		if !eB.IsUint64() {
			return fmt.Errorf("value for e is too large")
		}
		e := eB.Uint64()
		nB, err := jwkBase64ToBigInt(values["n"])
		if err != nil {
			return fmt.Errorf("while reading n: %w", err)
		}

		dA, ok := values["d"]
		if ok {
			// private key
			dB, err := jwkBase64ToBigInt(dA)
			if err != nil {
				return fmt.Errorf("while reading d: %w", err)
			}
			res := &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: nB,
					E: int(e),
				},
				D: dB,
			}
			if err = res.Validate(); err != nil {
				return fmt.Errorf("invalid RSA private key: %w", err)
			}
			jwk.PrivateKey = res
			jwk.PublicKey = res.PublicKey
			break
		}

		// public only
		jwk.PublicKey = &rsa.PublicKey{
			N: nB,
			E: int(e),
		}
		break
	case "EC":
		var crv elliptic.Curve
		switch values["crv"].(string) {
		case "P-224":
			crv = elliptic.P224()
		case "P-256":
			crv = elliptic.P256()
		case "P-384":
			crv = elliptic.P384()
		case "P-521":
			crv = elliptic.P521()
		default:
			return fmt.Errorf("unsupported curve %s", values["crv"])
		}

		// x, y and d in private key, only x and y if public
		x, err := jwkBase64ToBigInt(values["x"])
		if err != nil {
			return fmt.Errorf("while reading x: %w", err)
		}
		y, err := jwkBase64ToBigInt(values["y"])
		if err != nil {
			return fmt.Errorf("while reading y: %w", err)
		}
		dA, ok := values["d"]
		if ok {
			// private key
			dB, err := jwkBase64ToBigInt(dA)
			if err != nil {
				return fmt.Errorf("while reading d: %w", err)
			}
			res := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: crv,
					X:     x,
					Y:     y,
				},
				D: dB,
			}
			// TODO validate key?
			jwk.PrivateKey = res
			jwk.PublicKey = res.PublicKey
			break
		}

		// public only
		jwk.PublicKey = &ecdsa.PublicKey{
			Curve: crv,
			X:     x,
			Y:     y,
		}
		break
	default:
		return fmt.Errorf("unsupported value for kty=%s", kty)
	}

	if kid, ok := values["kid"]; ok {
		switch s := kid.(type) {
		case string:
			jwk.KeyID = s
		case []byte:
			jwk.KeyID = string(s)
		}
	}
	if alg, ok := values["alg"].(string); ok {
		jwk.Algo = alg
	}
	if use, ok := values["use"].(string); ok {
		jwk.Use = use
	}

	return nil
}

func (jwk *JWK) MarshalJSON() ([]byte, error) {
	return json.Marshal(jwk.ExportValues())
}

func (jwk *JWK) ExportValues() map[string]any {
	res := jwk.ExportRequiredValues()

	if jwk.KeyID != "" {
		res["kid"] = jwk.KeyID
	}
	if jwk.Algo != "" {
		res["alg"] = jwk.Algo
	}
	if jwk.Use != "" {
		res["use"] = jwk.Use
	}
	if jwk.Ext {
		res["ext"] = true
	}
	if len(jwk.KeyOps) != 0 {
		res["key_ops"] = jwk.KeyOps
	}

	return res
}

func (jwk *JWK) ExportRequiredValues() map[string]any {
	if jwk.PrivateKey != nil {
		switch v := jwk.PrivateKey.(type) {
		case *rsa.PrivateKey:
			return map[string]any{
				"kty": "RSA",
				"e":   jwkBigIntToBase64(big.NewInt(int64(v.E))),
				"n":   jwkBigIntToBase64(v.N),
				"d":   jwkBigIntToBase64(v.D),
			}
		case *ecdsa.PrivateKey:
			return map[string]any{
				"kty": "EC",
				"crv": v.Curve.Params().Name,
				"d":   jwkBigIntToBase64(v.D),
				"x":   jwkBigIntToBase64(v.PublicKey.X),
				"y":   jwkBigIntToBase64(v.PublicKey.Y),
			}
		}
	}
	if jwk.PublicKey != nil {
		return jwk.ExportRequiredPublicValues()
	}
	return nil
}

func (jwk *JWK) ExportRequiredPublicValues() map[string]any {
	switch v := jwk.PublicKey.(type) {
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA",
			"e":   jwkBigIntToBase64(big.NewInt(int64(v.E))),
			"n":   jwkBigIntToBase64(v.N),
		}
	case *ecdsa.PublicKey:
		return map[string]any{
			"kty": "EC",
			"crv": v.Curve.Params().Name,
			"x":   jwkBigIntToBase64(v.X),
			"y":   jwkBigIntToBase64(v.Y),
		}
	}
	return nil
}

func jwkBase64ToBigInt(v any) (*big.Int, error) {
	var vText string

	// detect type of input
	switch xv := v.(type) {
	case string:
		vText = xv
	case []byte:
		vText = string(xv)
	default:
		return nil, fmt.Errorf("unsupported base64 to int type %T", v)
	}

	// parse base64
	vBin, err := base64.RawURLEncoding.DecodeString(vText)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 to int input: %w", err)
	}

	// allocate/set big.Int
	res := new(big.Int)
	res.SetBytes(vBin)

	return res, nil
}

func jwkBigIntToBase64(v *big.Int) string {
	// so much easier!
	return base64.RawURLEncoding.EncodeToString(v.Bytes())
}
