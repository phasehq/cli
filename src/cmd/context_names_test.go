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
	// The zero-value client has no host, so the lookup fails at request time
	// without any network I/O and the selectors are returned as-is.
	app, env := contextNames(&sdk.Phase{}, secrets, "my-app", "Development", "")
	if app != "my-app" || env != "Development" {
		t.Fatalf("unexpected fallback: got %q/%q want %q/%q", app, env, "my-app", "Development")
	}
}

func TestEmptyPathHint(t *testing.T) {
	// No path filter means every path was already searched — nothing to suggest.
	if got := emptyPathHint("", "inject"); got != "" {
		t.Fatalf("expected no hint for an empty path filter, got %q", got)
	}

	hint := emptyPathHint("/", "inject")
	if !strings.Contains(hint, `--path ""`) {
		t.Fatalf("hint should suggest --path \"\", got %q", hint)
	}
	if !strings.Contains(hint, "inject") {
		t.Fatalf("hint should use the caller's verb, got %q", hint)
	}
}
