package display

import (
	"io"
	"os"
	"strings"
	"testing"

	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// captureStdout runs fn and returns everything it wrote to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// An empty result set must still name the app and environment that was queried,
// otherwise a path filter that matches nothing reads as a broken .phase.json.
func TestRenderSecretsTreeEmptyShowsContext(t *testing.T) {
	out := captureStdout(t, func() {
		RenderSecretsTree(nil, false, "my-app", "Development", "/")
	})

	for _, want := range []string{"my-app", "Development", `--path ""`} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// Without a path filter every path was searched, so suggesting --path "" would
// be a dead end.
func TestRenderSecretsTreeEmptyWithoutPathFilterHasNoHint(t *testing.T) {
	out := captureStdout(t, func() {
		RenderSecretsTree(nil, false, "my-app", "Production", "")
	})

	if !strings.Contains(out, "my-app") || !strings.Contains(out, "Production") {
		t.Fatalf("expected output to name the app and environment, got:\n%s", out)
	}
	if strings.Contains(out, `--path ""`) {
		t.Fatalf("did not expect a path hint when no path filter was applied, got:\n%s", out)
	}
}

// The header comes from the resolved context, not from the first row.
func TestRenderSecretsTreeHeaderUsesResolvedContext(t *testing.T) {
	secrets := []sdk.SecretResult{{Key: "SECRET_1", Value: "v", Path: "/one"}}

	out := captureStdout(t, func() {
		RenderSecretsTree(secrets, false, "my-app", "Development", "/one")
	})

	if !strings.Contains(out, "Application: my-app") {
		t.Fatalf("expected resolved application in header, got:\n%s", out)
	}
	if !strings.Contains(out, "Environment: Development") {
		t.Fatalf("expected resolved environment in header, got:\n%s", out)
	}
	if !strings.Contains(out, "SECRET_1") {
		t.Fatalf("expected the secret row to render, got:\n%s", out)
	}
}
