package cmd

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestResolveTokenName(t *testing.T) {
	if got := resolveTokenName("", "alice", "laptop"); got != "alice@laptop" {
		t.Fatalf("empty flag: got %q, want %q", got, "alice@laptop")
	}
	if got := resolveTokenName("   ", "alice", "laptop"); got != "alice@laptop" {
		t.Fatalf("whitespace flag: got %q, want %q", got, "alice@laptop")
	}
	if got := resolveTokenName("  ci-prod-api  ", "alice", "laptop"); got != "ci-prod-api" {
		t.Fatalf("set flag: got %q, want %q", got, "ci-prod-api")
	}
}

func TestResolveWebAuthPort(t *testing.T) {
	// Neither flag nor env set: caller should fall back to a random port.
	if port, ok, err := resolveWebAuthPort(false, 0, ""); ok || err != nil || port != 0 {
		t.Fatalf("unset: got (%d, %v, %v), want (0, false, nil)", port, ok, err)
	}

	// Flag set: takes precedence and is returned.
	if port, ok, err := resolveWebAuthPort(true, 8002, "9000"); !ok || err != nil || port != 8002 {
		t.Fatalf("flag set: got (%d, %v, %v), want (8002, true, nil)", port, ok, err)
	}

	// Env set, flag unset: env is used (whitespace trimmed).
	if port, ok, err := resolveWebAuthPort(false, 0, "  9000 "); !ok || err != nil || port != 9000 {
		t.Fatalf("env set: got (%d, %v, %v), want (9000, true, nil)", port, ok, err)
	}

	// Out-of-range flag is an error.
	if _, ok, err := resolveWebAuthPort(true, 70000, ""); ok || err == nil {
		t.Fatalf("out-of-range flag: got (ok=%v, err=%v), want (false, error)", ok, err)
	}
	if _, ok, err := resolveWebAuthPort(true, 0, ""); ok || err == nil {
		t.Fatalf("zero flag: got (ok=%v, err=%v), want (false, error)", ok, err)
	}

	// Non-numeric and out-of-range env values are errors.
	if _, ok, err := resolveWebAuthPort(false, 0, "abc"); ok || err == nil {
		t.Fatalf("non-numeric env: got (ok=%v, err=%v), want (false, error)", ok, err)
	}
	if _, ok, err := resolveWebAuthPort(false, 0, "70000"); ok || err == nil {
		t.Fatalf("out-of-range env: got (ok=%v, err=%v), want (false, error)", ok, err)
	}
}

func TestEncodeWebAuthPayload(t *testing.T) {
	// With a lifetime: all fields present, name with hyphens preserved.
	encoded, err := encodeWebAuthPayload(8002, "abc123", "ci-prod-api", 604800)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("payload is not valid base64: %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if fields["port"].(float64) != 8002 {
		t.Fatalf("port: got %v, want 8002", fields["port"])
	}
	if fields["publicKey"] != "abc123" {
		t.Fatalf("publicKey: got %v, want abc123", fields["publicKey"])
	}
	if fields["name"] != "ci-prod-api" {
		t.Fatalf("name: got %v, want ci-prod-api", fields["name"])
	}
	if fields["lifetime"].(float64) != 604800 {
		t.Fatalf("lifetime: got %v, want 604800", fields["lifetime"])
	}

	// Without a lifetime (0): the field is omitted so the token never expires.
	encoded, err = encodeWebAuthPayload(8002, "abc123", "alice@laptop", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, _ = base64.StdEncoding.DecodeString(encoded)
	fields = map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if _, ok := fields["lifetime"]; ok {
		t.Fatalf("lifetime should be omitted when zero, got %v", fields["lifetime"])
	}
}
