package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KarpelesLab/jwt"
)

func TestGetString(t *testing.T) {
	tok := jwt.New()
	p := tok.Payload()

	p.Set("str", "hello")
	p.Set("int64", int64(42))
	p.Set("float64", 3.14)
	p.Set("bytes", []byte("raw"))
	p.Set("nil", nil)

	tests := []struct {
		key    string
		expect string
	}{
		{"str", "hello"},
		{"int64", "42"},
		{"float64", "3.14"},
		{"bytes", "raw"},
		{"nil", ""},
		{"missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := p.GetString(tt.key)
			if got != tt.expect {
				t.Errorf("GetString(%q) = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestGetStringJsonNumber(t *testing.T) {
	// simulate json.Number as returned by json.Decoder with UseNumber
	tok, err := jwt.ParseString("eyJhbGciOiJIUzI1NiJ9.eyJ2YWwiOjEyMzQ1fQ.X")
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	v := tok.Payload().Get("val")
	if _, ok := v.(json.Number); !ok {
		t.Fatalf("expected json.Number, got %T", v)
	}
	s := tok.Payload().GetString("val")
	if s != "12345" {
		t.Errorf("expected '12345', got %q", s)
	}
}

func TestGetInt(t *testing.T) {
	tok := jwt.New()
	p := tok.Payload()

	p.Set("int64", int64(42))
	p.Set("float64", 3.99)
	p.Set("str", "123")
	p.Set("bool_true", true)
	p.Set("bool_false", false)
	p.Set("nil", nil)
	p.Set("uint", uint(7))

	tests := []struct {
		key    string
		expect int64
	}{
		{"int64", 42},
		{"float64", 3},
		{"str", 123},
		{"bool_true", 1},
		{"bool_false", 0},
		{"nil", 0},
		{"missing", 0},
		{"uint", 7},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := p.GetInt(tt.key)
			if got != tt.expect {
				t.Errorf("GetInt(%q) = %d, want %d", tt.key, got, tt.expect)
			}
		})
	}
}

func TestGetIntJsonNumber(t *testing.T) {
	tok, err := jwt.ParseString("eyJhbGciOiJIUzI1NiJ9.eyJ2YWwiOjk5OX0.X")
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	v := tok.Payload().GetInt("val")
	if v != 999 {
		t.Errorf("expected 999, got %d", v)
	}
}

func TestGetFloat(t *testing.T) {
	tok := jwt.New()
	p := tok.Payload()

	p.Set("float64", 3.14)
	p.Set("int64", int64(42))
	p.Set("str", "2.718")
	p.Set("nil", nil)
	p.Set("uint", uint(5))

	tests := []struct {
		key    string
		expect float64
	}{
		{"float64", 3.14},
		{"int64", 42.0},
		{"str", 2.718},
		{"nil", 0},
		{"missing", 0},
		{"uint", 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := p.GetFloat(tt.key)
			if got != tt.expect {
				t.Errorf("GetFloat(%q) = %f, want %f", tt.key, got, tt.expect)
			}
		})
	}
}

func TestGetFloatJsonNumber(t *testing.T) {
	tok, err := jwt.ParseString("eyJhbGciOiJIUzI1NiJ9.eyJ2YWwiOjEuNX0.X")
	if err != nil {
		t.Fatalf("failed to parse: %s", err)
	}
	v := tok.Payload().GetFloat("val")
	if v != 1.5 {
		t.Errorf("expected 1.5, got %f", v)
	}
}

func TestGetNumericDate(t *testing.T) {
	tok := jwt.New()
	now := time.Now()
	tok.Payload().Set("iat", now.Unix())

	got := tok.Payload().GetNumericDate("iat")
	if got.Unix() != now.Unix() {
		t.Errorf("expected %d, got %d", now.Unix(), got.Unix())
	}

	// missing key
	got = tok.Payload().GetNumericDate("missing")
	if !got.IsZero() {
		t.Error("expected zero time for missing key")
	}
}

func TestGetStringReflectTypes(t *testing.T) {
	tok := jwt.New()
	p := tok.Payload()

	p.Set("int32", int32(42))
	p.Set("uint64", uint64(99))
	p.Set("float32", float32(1.5))
	p.Set("complex64", complex64(1+2i))
	p.Set("complex128", complex128(3+4i))
	p.Set("struct", struct{}{}) // unsupported type

	if p.GetString("int32") != "42" {
		t.Errorf("int32: got %q", p.GetString("int32"))
	}
	if p.GetString("uint64") != "99" {
		t.Errorf("uint64: got %q", p.GetString("uint64"))
	}
	if p.GetString("float32") != "1.5" {
		t.Errorf("float32: got %q", p.GetString("float32"))
	}
	if p.GetString("complex64") == "" {
		t.Error("complex64 should return non-empty string")
	}
	if p.GetString("complex128") == "" {
		t.Error("complex128 should return non-empty string")
	}
	if p.GetString("struct") != "" {
		t.Error("unsupported type should return empty string")
	}
}

func TestGetIntReflectFloat(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("f32", float32(7.9))
	if tok.Payload().GetInt("f32") != 7 {
		t.Errorf("expected 7, got %d", tok.Payload().GetInt("f32"))
	}
}

func TestGetFloatReflectFloat32(t *testing.T) {
	tok := jwt.New()
	tok.Payload().Set("f32", float32(2.5))
	if tok.Payload().GetFloat("f32") != 2.5 {
		t.Errorf("expected 2.5, got %f", tok.Payload().GetFloat("f32"))
	}
}
