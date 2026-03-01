package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBoolFlag(t *testing.T) {
	falseCases := []string{"false", "FALSE", "no", "0", "  no  "}
	for _, tc := range falseCases {
		if ParseBoolFlag(tc) {
			t.Fatalf("expected false for %q", tc)
		}
	}

	trueCases := []string{"true", "yes", "1", "", "random"}
	for _, tc := range trueCases {
		if !ParseBoolFlag(tc) {
			t.Fatalf("expected true for %q", tc)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `# comment
FOO=bar
lower_case = "quoted value"
SINGLE='abc'
NO_EQUALS
SPACED = value with spaces
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	pairs, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("parse env file: %v", err)
	}

	got := map[string]string{}
	for _, p := range pairs {
		got[p.Key] = p.Value
	}

	want := map[string]string{
		"FOO":        "bar",
		"LOWER_CASE": "quoted value",
		"SINGLE":     "abc",
		"SPACED":     "value with spaces",
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected key count: got %d want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("mismatch for %s: got %q want %q", k, got[k], v)
		}
	}
}
