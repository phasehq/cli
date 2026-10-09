package cmd

import (
	"strings"
	"testing"

	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

func TestContextNamesReadsNamesFromSecrets(t *testing.T) {
	secrets := []sdk.SecretResult{
		{Key: "A", Application: "my-app", Environment: "Development"},
		{Key: "B", Application: "my-app", Environment: "Development"},
	}

	// A nil client is safe here: names come off the rows, so no lookup is made.
	app, env := contextNames(nil, secrets, "my", "dev", "")
	if app != "my-app" {
		t.Fatalf("unexpected application: got %q want %q", app, "my-app")
	}
	if env != "Development" {
		t.Fatalf("unexpected environment: got %q want %q", env, "Development")
	}
}

func TestContextNamesIgnoresBlankNamesOnRows(t *testing.T) {
	secrets := []sdk.SecretResult{{Key: "A"}}

	// With no usable names on the rows, contextNames falls back to a lookup.
	// PHASE_SERVICE_TOKEN disables the on-disk user-data cache (see
	// getCacheDir), so a developer's real cache can't leak into the test, and
	// the zero-value client has no host, so the lookup fails at request time
	// without any network I/O and the selectors are returned as-is.
	t.Setenv("PHASE_SERVICE_TOKEN", "test")
	t.Setenv("PHASE_OFFLINE", "")
	app, env := contextNames(&sdk.Phase{}, secrets, "my-app", "Development", "")
	if app != "my-app" || env != "Development" {
		t.Fatalf("unexpected fallback: got %q/%q want %q/%q", app, env, "my-app", "Development")
	}
}

func TestEmptyResultHint(t *testing.T) {
	// No filters means the environment is genuinely empty — nothing to suggest.
	if got := emptyResultHint("", "", "inject", false); got != "" {
		t.Fatalf("expected no hint without filters, got %q", got)
	}

	hint := emptyResultHint("/", "", "inject", false)
	if !strings.Contains(hint, `--path ""`) {
		t.Fatalf("path hint should suggest --path \"\", got %q", hint)
	}
	if !strings.Contains(hint, "inject") {
		t.Fatalf("hint should use the caller's verb, got %q", hint)
	}

	// A tag filter is a likelier cause than the path, so it must be named; the
	// path suggestion alone would misdirect.
	hint = emptyResultHint("/", "backend", "inject", false)
	if !strings.Contains(hint, "backend") || !strings.Contains(hint, "--tags") {
		t.Fatalf("tag+path hint should name the tag filter, got %q", hint)
	}
	if !strings.Contains(hint, `--path ""`) {
		t.Fatalf("tag+path hint should still mention the path filter, got %q", hint)
	}

	// Tags with no path filter: the path suggestion would be a dead end.
	hint = emptyResultHint("", "backend", "list", false)
	if !strings.Contains(hint, "--tags") {
		t.Fatalf("tag hint should name the tag filter, got %q", hint)
	}
	if strings.Contains(hint, `--path ""`) {
		t.Fatalf("tag-only hint should not suggest a path change, got %q", hint)
	}
}
