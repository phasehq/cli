package cmd

import (
	"context"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
)

// A format that escapes a value writes text the raw value does not match, so
// the escaped form is registered as well, under the secret's own id.
func TestExportRegistersTheFormatsEscapedFormToo(t *testing.T) {
	const value = `pa%ss"wo&rd<q7Lm2Zr6Tx4Nb9Wc1Ke7Hy3%"&`
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.environments["app-orders/development"] = []consoleSecret{
		{ID: "s-1", Key: "API_KEY", Value: value, Path: "/", Type: "secret"},
	}
	downSession(t)
	captureLeakWarnings(t)
	var registered []leakguard.Value
	previous := leakRegister
	leakRegister = func(_ context.Context, _ leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
		registered = append(registered, values...)
		return leakguard.Result{Added: len(values)}, nil
	}
	t.Cleanup(func() { leakRegister = previous })

	for format, escaped := range map[string]string{
		"ini":    `pa%%ss"wo&rd<q7Lm2Zr6Tx4Nb9Wc1Ke7Hy3%%"&`,
		"csv":    `pa%ss""wo&rd<q7Lm2Zr6Tx4Nb9Wc1Ke7Hy3%""&`,
		"xml":    `pa%ss&#34;wo&amp;rd&lt;q7Lm2Zr6Tx4Nb9Wc1Ke7Hy3%&#34;&amp;`,
		"dotenv": value,
		"json":   value,
	} {
		registered = nil
		if _, stderr, err := runPhaseCommand(t, "", "secrets", "export", "--app-id", "app-orders", "--format", format); err != nil {
			t.Fatalf("%s: %v %s", format, err, stderr)
		}
		forms := map[string]string{}
		for _, v := range registered {
			forms[v.Value] = v.ID
		}
		if forms[value] == "" || forms[escaped] != forms[value] {
			t.Fatalf("%s: registered %+v, want %q and %q under one id", format, registered, value, escaped)
		}
		if escaped == value && len(registered) != 1 {
			t.Fatalf("%s: a format that writes the value as it is registered %d forms", format, len(registered))
		}
	}
}
