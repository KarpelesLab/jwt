package jwt_test

import (
	"testing"

	"github.com/KarpelesLab/jwt"
)

func TestParseStringInvalid(t *testing.T) {
	_, err := jwt.ParseString("notavalidtoken")
	if err == nil {
		t.Error("should fail on invalid token")
	}
}

func TestGetAlgo(t *testing.T) {
	tok := jwt.New(jwt.HS256)
	algo := tok.GetAlgo()
	if algo == nil || algo.String() != "HS256" {
		t.Errorf("expected HS256, got %v", algo)
	}

	// token without algo
	tok2 := jwt.New()
	algo = tok2.GetAlgo()
	if algo != nil {
		t.Errorf("expected nil algo, got %v", algo)
	}
}

func TestGetKeyId(t *testing.T) {
	tok := jwt.New(jwt.HS256)
	tok.Header().Set("kid", "mykey123")
	if tok.GetKeyId() != "mykey123" {
		t.Errorf("expected mykey123, got %s", tok.GetKeyId())
	}

	// no kid set
	tok2 := jwt.New()
	if tok2.GetKeyId() != "" {
		t.Errorf("expected empty kid, got %s", tok2.GetKeyId())
	}
}

func TestGetContentType(t *testing.T) {
	// default
	tok := jwt.New()
	if tok.GetContentType() != "application/jwt" {
		t.Errorf("expected application/jwt, got %s", tok.GetContentType())
	}

	// short form without slash
	tok.Header().Set("cty", "jwt")
	if tok.GetContentType() != "application/jwt" {
		t.Errorf("expected application/jwt, got %s", tok.GetContentType())
	}

	// full form with slash
	tok.Header().Set("cty", "application/example")
	if tok.GetContentType() != "application/example" {
		t.Errorf("expected application/example, got %s", tok.GetContentType())
	}
}

func TestSetRawPayload(t *testing.T) {
	tok := jwt.New(jwt.HS256)
	err := tok.SetRawPayload([]byte("hello world"), "octet-stream")
	if err != nil {
		t.Fatalf("SetRawPayload failed: %s", err)
	}
	if tok.Header().Get("cty") != "octet-stream" {
		t.Error("cty not set")
	}

	raw, err := tok.GetRawPayload()
	if err != nil {
		t.Fatalf("GetRawPayload failed: %s", err)
	}
	if string(raw) != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", string(raw))
	}

	// without cty
	tok2 := jwt.New(jwt.HS256)
	err = tok2.SetRawPayload([]byte("data"), "")
	if err != nil {
		t.Fatalf("SetRawPayload without cty failed: %s", err)
	}
}

func TestGetRawPayload(t *testing.T) {
	// with payload set
	tok := jwt.New()
	tok.Payload().Set("foo", "bar")
	raw, err := tok.GetRawPayload()
	if err != nil {
		t.Fatalf("GetRawPayload failed: %s", err)
	}
	if len(raw) == 0 {
		t.Error("expected non-empty payload")
	}

	// empty token
	tok2 := jwt.New()
	raw, err = tok2.GetRawPayload()
	if err != nil {
		t.Fatalf("GetRawPayload on empty token failed: %s", err)
	}
	if string(raw) != "{}" {
		t.Errorf("expected empty json, got '%s'", string(raw))
	}
}

func TestGetRawSignatureNoSig(t *testing.T) {
	tok := jwt.New()
	_, err := tok.GetRawSignature()
	if err == nil {
		t.Error("should fail on unsigned token")
	}
}

func TestHeaderHasAndUnset(t *testing.T) {
	tok := jwt.New(jwt.HS256)
	if !tok.Header().Has("alg") {
		t.Error("expected header to have alg")
	}
	tok.Header().Unset("alg")
	if tok.Header().Has("alg") {
		t.Error("expected alg to be unset")
	}
}

func TestNilHeaderAndPayload(t *testing.T) {
	// Set on nil header
	var h jwt.Header
	err := h.Set("key", "val")
	if err == nil {
		t.Error("Set on nil header should return error")
	}

	// Get on nil header
	if h.Get("key") != "" {
		t.Error("Get on nil header should return empty")
	}

	// Has on nil header
	if h.Has("key") {
		t.Error("Has on nil header should return false")
	}

	// Set on nil payload
	var p jwt.Payload
	err = p.Set("key", "val")
	if err == nil {
		t.Error("Set on nil payload should return error")
	}

	// Get on nil payload
	if p.Get("key") != nil {
		t.Error("Get on nil payload should return nil")
	}

	// Has on nil payload
	if p.Has("key") {
		t.Error("Has on nil payload should return false")
	}
}
