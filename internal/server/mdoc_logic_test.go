package server

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestBuildDeviceRequest_Base64URLEncodedString(t *testing.T) {
	got, err := BuildDeviceRequest()
	if err != nil {
		t.Fatalf("BuildDeviceRequest() error = %v", err)
	}
	if got == "" {
		t.Fatal("BuildDeviceRequest() returned empty string")
	}
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(got)
	if err != nil {
		t.Fatalf("failed to base64url-decode: %v", err)
	}
	var m map[string]interface{}
	if err := cbor.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to CBOR-decode: %v", err)
	}
	if v, ok := m["version"].(string); !ok || v != "1.1" {
		t.Fatalf("unexpected version: %#v", m["version"])
	}
	if _, ok := m["docRequests"]; !ok {
		t.Fatalf("missing docRequests")
	}
	if _, ok := m["readerAuthAll"]; !ok {
		t.Fatalf("missing readerAuthAll")
	}
}
