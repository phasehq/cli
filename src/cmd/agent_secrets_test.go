package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi/providerrulestest"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
	gokeyring "github.com/zalando/go-keyring"
)

const agentTestLookup = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

func agentTestToken() string {
	return "pss_agent:v1:" + agentTestLookup + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

// Values a secret holds. None of them may appear where an Agent reads a
// refusal, and the secret-typed ones never appear in masked output.
const (
	agentSecretValue = "live-secret-value-0123456789"
	agentSealedValue = "sealed-value-0123456789"
	agentConfigValue = "config-value"
)

type consoleSecret struct {
	ID    string   `json:"id"`
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Path  string   `json:"path"`
	Tags  []string `json:"tags"`
	Type  string   `json:"type"`
}

type consoleCall struct {
	method string
	path   string
	query  url.Values
	body   string
}

// fakeAgentConsole implements the app access listing and the public secrets
// API as the contract describes them for an Agent caller.
type fakeAgentConsole struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	calls  []consoleCall
	// environments holds the secrets of each granted environment, by
	// "<app id>/<environment name in lower case>".
	environments map[string][]consoleSecret
	nextID       int
	// fail, when it returns a status, answers a secrets call instead.
	fail func(r *http.Request) (int, string, http.Header)
	// appAccess, when set, replaces the app-access listing.
	appAccess string
}

func newFakeAgentConsole(t *testing.T) *fakeAgentConsole {
	t.Helper()
	console := &fakeAgentConsole{t: t, environments: map[string][]consoleSecret{
		"app-orders/development": {
			{ID: "s-api", Key: "API_KEY", Value: agentSecretValue, Path: "/", Tags: []string{"backend"}, Type: "secret"},
			{ID: "s-sealed", Key: "SIGNING_KEY", Value: agentSealedValue, Path: "/", Tags: []string{}, Type: "sealed"},
			{ID: "s-config", Key: "CONFIG_KEY", Value: agentConfigValue, Path: "/", Tags: []string{"frontend"}, Type: "config"},
			{ID: "s-ref", Key: "REF_KEY", Value: "${CONFIG_KEY}", Path: "/", Tags: []string{}, Type: "config"},
			{ID: "s-nested", Key: "NESTED_KEY", Value: "nested-value", Path: "/backend", Tags: []string{}, Type: "config"},
		},
		"app-orders/staging": {},
	}}
	console.server = httptest.NewServer(http.HandlerFunc(console.serve))
	t.Cleanup(console.server.Close)
	return console
}

func (c *fakeAgentConsole) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, consoleCall{method: r.Method, path: r.URL.Path, query: r.URL.Query(), body: string(body)})
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.Path, "/service/public/") {
		c.t.Errorf("an Agent login called %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Header.Get("Authorization") != "Bearer Agent "+agentTestLookup {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"The Agent token is not valid.","code":"invalid_token"}`))
		return
	}
	if r.URL.Path == "/service/public/v1/agents/app-access/" {
		if c.appAccess != "" {
			_, _ = w.Write([]byte(c.appAccess))
			return
		}
		_, _ = w.Write([]byte(`{"schemaVersion":1,"apps":[{"connectionId":"connection-orders","connectionName":"orders-service secrets","grantId":"grant-orders",` +
			`"app":{"id":"app-orders","name":"orders-service"},"environments":[{"id":"env-dev","name":"Development","envType":"dev"},{"id":"env-staging","name":"Staging","envType":"staging"}],` +
			`"access":{"read":{"effect":"allow"},"create":{"effect":"allow"},"update":{"effect":"allow"},"delete":{"effect":"allow"}},"grantExpiresAt":null}],"expired":[]}`))
		return
	}
	if r.URL.Path != "/service/public/v1/secrets/" {
		c.t.Errorf("unexpected Console route %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if c.fail != nil {
		if status, response, headers := c.fail(r); status != 0 {
			for name, values := range headers {
				w.Header()[name] = values
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(response))
			return
		}
	}
	query := r.URL.Query()
	for _, refused := range []string{"dynamic", "lease", "lease_ttl", "include_dynamic"} {
		if query.Has(refused) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Dynamic secrets are not available to Agents yet.","code":"agent_dynamic_unsupported"}`))
			return
		}
	}
	environment := query.Get("app_id") + "/" + strings.ToLower(query.Get("env"))
	secrets, granted := c.environments[environment]
	if !granted {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"error":"This Workflow has no access to %s.","code":"agent_grant_missing","request":{"kind":"setup","title":"Read secrets","action":{"type":"agent_connection.app_access","version":1,"appId":%q,"environments":[%q],"access":"read"}}}`,
			environment, query.Get("app_id"), query.Get("env"))
		return
	}
	var payload struct {
		Secrets json.RawMessage `json:"secrets"`
	}
	if r.Method != http.MethodGet {
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		var result []consoleSecret
		for _, secret := range secrets {
			if (query.Get("path") != "" && secret.Path != query.Get("path")) || (query.Get("key") != "" && secret.Key != query.Get("key")) {
				continue
			}
			if query.Get("raw") != "true" && strings.HasPrefix(secret.Value, "${") {
				secret.Value = "resolved-reference"
			}
			result = append(result, secret)
		}
		if result == nil {
			result = []consoleSecret{}
		}
		_ = json.NewEncoder(w).Encode(result)
	case http.MethodPost:
		var writes []struct {
			Key, Value, Path, Type string
		}
		_ = json.Unmarshal(payload.Secrets, &writes)
		for _, write := range writes {
			c.nextID++
			kind := write.Type
			if kind == "" {
				kind = "secret"
			}
			secrets = append(secrets, consoleSecret{ID: fmt.Sprintf("s-new-%d", c.nextID), Key: strings.ToUpper(write.Key), Value: write.Value, Path: write.Path, Tags: []string{}, Type: kind})
		}
		c.environments[environment] = secrets
		_, _ = w.Write([]byte(`[]`))
	case http.MethodPut:
		var writes []map[string]string
		_ = json.Unmarshal(payload.Secrets, &writes)
		for _, write := range writes {
			for index := range secrets {
				if secrets[index].ID != write["id"] {
					continue
				}
				if value, present := write["value"]; present {
					secrets[index].Value = value
				}
				if path, present := write["path"]; present {
					secrets[index].Path = path
				}
				if kind, present := write["type"]; present {
					secrets[index].Type = kind
				}
			}
		}
		_, _ = w.Write([]byte(`[]`))
	case http.MethodDelete:
		var ids []string
		_ = json.Unmarshal(payload.Secrets, &ids)
		kept := secrets[:0]
		for _, secret := range secrets {
			if !slices.Contains(ids, secret.ID) {
				kept = append(kept, secret)
			}
		}
		c.environments[environment] = kept
		w.WriteHeader(http.StatusOK)
	}
}

func (c *fakeAgentConsole) takeCalls() []consoleCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	calls := c.calls
	c.calls = nil
	return calls
}

func secretsCalls(calls []consoleCall) []consoleCall {
	var result []consoleCall
	for _, call := range calls {
		if call.path == "/service/public/v1/secrets/" {
			result = append(result, call)
		}
	}
	return result
}

// isolateAgentCommand gives a command test a throwaway home, config, Phase
// secrets directory and working directory, no harness, no Phase AI session
// and no offline mode. The Agent login comes from PHASE_SERVICE_TOKEN unless
// the test stores one in a mocked keyring.
func isolateAgentCommand(t *testing.T, host string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, name := range []string{"CLAUDECODE", "CURSOR_AGENT", "CODEX", "OPENCODE", "AGENT", "PHASE_AI_ENABLED", "PHASE_OFFLINE"} {
		t.Setenv(name, "")
	}
	t.Setenv("PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH", "0")
	t.Setenv("PHASE_HOST", host)
	t.Setenv("PHASE_SERVICE_TOKEN", agentTestToken())
	t.Setenv("SHELL", "/bin/sh")
	originalConfig, originalSecretsDir := config.ConfigFilePath, config.PhaseSecretsDir
	config.PhaseSecretsDir = filepath.Join(home, ".phase", "secrets")
	config.ConfigFilePath = filepath.Join(config.PhaseSecretsDir, "config.json")
	t.Cleanup(func() {
		config.ConfigFilePath, config.PhaseSecretsDir = originalConfig, originalSecretsDir
		ai.SetAgentLogin(false)
	})
	ai.SetAgentLogin(false)
	work := t.TempDir()
	t.Chdir(work)
	return work
}

// runPhaseCommand runs the CLI in process with stdin from the given text and
// returns what it wrote to stdout and stderr. Flags are reset afterwards so
// one run never leaks into the next.
func runPhaseCommand(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	directory := t.TempDir()
	stdout, _ := os.Create(filepath.Join(directory, "stdout"))
	stderr, _ := os.Create(filepath.Join(directory, "stderr"))
	input := filepath.Join(directory, "stdin")
	if err := os.WriteFile(input, []byte(stdin), 0o600); err != nil {
		t.Fatal(err)
	}
	stdinFile, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	originalOut, originalErr, originalIn := os.Stdout, os.Stderr, os.Stdin
	os.Stdout, os.Stderr, os.Stdin = stdout, stderr, stdinFile
	rootCmd.SetArgs(args)
	executeErr := rootCmd.Execute()
	os.Stdout, os.Stderr, os.Stdin = originalOut, originalErr, originalIn
	rootCmd.SetArgs(nil)
	resetCommandFlags(rootCmd)
	_ = stdout.Close()
	_ = stderr.Close()
	_ = stdinFile.Close()
	out, _ := os.ReadFile(stdout.Name())
	errOut, _ := os.ReadFile(stderr.Name())
	return string(out), string(errOut), executeErr
}

func resetCommandFlags(command *cobra.Command) {
	command.Flags().VisitAll(resetFlag)
	for _, child := range command.Commands() {
		resetCommandFlags(child)
	}
}

// resetFlag restores one flag to its default. Its type is inferred from
// VisitAll, so the test needs no direct import of the flag package.
func resetFlag[F any](flag F) {
	value := reflect.ValueOf(flag).Elem()
	setter := value.FieldByName("Value").Interface().(interface{ Set(string) error })
	_ = setter.Set(value.FieldByName("DefValue").String())
	value.FieldByName("Changed").SetBool(false)
}

func TestAgentSecretsListGetAndExport(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)

	stdout, stderr, err := runPhaseCommand(t, "", "secrets", "list", "--app-id", "app-orders", "--env", "development", "--show")
	if err != nil {
		t.Fatalf("list: %v (stderr=%s)", err, stderr)
	}
	for _, want := range []string{"API_KEY", "SIGNING_KEY", "CONFIG_KEY", "NESTED_KEY", agentConfigValue, "${CONFIG_KEY}", "[REDACTED]", "orders-service", "Development"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("list output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, agentSecretValue) || strings.Contains(stdout, agentSealedValue) {
		t.Fatalf("list showed a secret value to an Agent:\n%s", stdout)
	}
	if !strings.Contains(stderr, "for Agents on purpose") {
		t.Fatalf("list did not say values are masked: %q", stderr)
	}
	calls := console.takeCalls()
	list := secretsCalls(calls)
	if len(calls) != 2 || calls[0].path != "/service/public/v1/agents/app-access/" || len(list) != 1 ||
		list[0].method != "GET" || list[0].query.Get("raw") != "true" || list[0].query.Has("path") ||
		list[0].query.Get("app_id") != "app-orders" || list[0].query.Get("env") != "Development" {
		t.Fatalf("list calls = %+v", calls)
	}

	stdout, _, err = runPhaseCommand(t, "", "secrets", "get", "REF_KEY", "--app-id", "app-orders")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || got["key"] != "REF_KEY" || got["value"] != "${CONFIG_KEY}" {
		t.Fatalf("get = %s (%v)", stdout, err)
	}
	get := secretsCalls(console.takeCalls())
	if len(get) != 1 || get[0].query.Get("raw") != "true" || get[0].query.Get("key") != "REF_KEY" || get[0].query.Get("path") != "/" {
		t.Fatalf("get calls = %+v", get)
	}
	stdout, _, err = runPhaseCommand(t, "", "secrets", "get", "api_key", "config_key", "--app-id", "app-orders")
	if err != nil || !strings.Contains(stdout, `"[REDACTED]"`) || !strings.Contains(stdout, agentConfigValue) || strings.Contains(stdout, agentSecretValue) {
		t.Fatalf("get several = %s (%v)", stdout, err)
	}
	if get := secretsCalls(console.takeCalls()); len(get) != 1 || get[0].query.Has("key") {
		t.Fatalf("a multi-key get narrowed by key: %+v", get)
	}
	_, _, err = runPhaseCommand(t, "", "secrets", "get", "NESTED_KEY", "--app-id", "app-orders")
	if err == nil || !strings.Contains(err.Error(), "No matching secrets found at path /") {
		t.Fatalf("get outside the path: %v", err)
	}
	console.takeCalls()

	stdout, _, err = runPhaseCommand(t, "", "secrets", "export", "--app-id", "app-orders", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var exported map[string]string
	if err := json.Unmarshal([]byte(stdout), &exported); err != nil {
		t.Fatalf("export json = %s (%v)", stdout, err)
	}
	// A config value holding a reference would print what it resolves to.
	if exported["CONFIG_KEY"] != agentConfigValue || exported["REF_KEY"] != "[REDACTED]" ||
		exported["API_KEY"] != "[REDACTED]" || exported["SIGNING_KEY"] != "[REDACTED]" || len(exported) != 4 {
		t.Fatalf("export = %v", exported)
	}
	exportCalls := secretsCalls(console.takeCalls())
	if len(exportCalls) != 2 || exportCalls[0].query.Has("raw") || exportCalls[0].query.Get("path") != "/" ||
		exportCalls[1].query.Get("raw") != "true" || exportCalls[1].query.Get("path") != "/" ||
		exportCalls[0].query.Has("dynamic") || exportCalls[0].query.Has("lease") {
		t.Fatalf("export calls = %+v", exportCalls)
	}
	for format, want := range map[string]string{
		"dotenv": "CONFIG_KEY=\"" + agentConfigValue + "\"",
		"yaml":   "CONFIG_KEY: " + agentConfigValue,
		"kv":     "CONFIG_KEY=" + agentConfigValue,
	} {
		stdout, _, err = runPhaseCommand(t, "", "secrets", "export", "CONFIG_KEY", "--app-id", "app-orders", "--format", format)
		if err != nil || !strings.Contains(stdout, want) {
			t.Fatalf("export %s = %q (%v)", format, stdout, err)
		}
	}
	console.takeCalls()

	// Tags filter as they do for other logins: on the client, by substring.
	stdout, _, err = runPhaseCommand(t, "", "secrets", "list", "--app-id", "app-orders", "--tags", "back")
	if err != nil || !strings.Contains(stdout, "API_KEY") || strings.Contains(stdout, "CONFIG_KEY") {
		t.Fatalf("list --tags = %s (%v)", stdout, err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Has("tags") {
		t.Fatalf("tags were sent to the Console: %+v", calls)
	}
	stdout, _, err = runPhaseCommand(t, "", "secrets", "list", "--app-id", "app-orders", "--path", "/backend")
	if err != nil || !strings.Contains(stdout, "NESTED_KEY") || strings.Contains(stdout, "API_KEY") {
		t.Fatalf("list --path = %s (%v)", stdout, err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Get("path") != "/backend" {
		t.Fatalf("list --path calls = %+v", calls)
	}
	// The app may also be chosen by name and the environment by name, exactly
	// but in any case.
	stdout, _, err = runPhaseCommand(t, "", "secrets", "list", "--app", "Orders-Service", "--env", "staging")
	if err != nil || !strings.Contains(stdout, "Staging") {
		t.Fatalf("list by name = %s (%v)", stdout, err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Get("env") != "Staging" || calls[0].query.Get("app_id") != "app-orders" {
		t.Fatalf("list by name calls = %+v", calls)
	}
}

// Export masks each secret by its own type, and for an Agent any config value
// whose unresolved form holds a reference.
func TestAgentExportMasksBySecretAndReference(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.environments["app-orders/development"] = []consoleSecret{
		{ID: "s-1", Key: "DUP", Value: agentSecretValue, Path: "/", Type: "secret"},
		{ID: "s-2", Key: "DUP", Value: "dup-config", Path: "/b", Type: "config"},
		{ID: "s-3", Key: "DSN", Value: "${API_KEY}", Path: "/", Type: "config"},
		{ID: "s-4", Key: "ODD", Value: agentSealedValue, Path: "/", Type: "Secret"},
		{ID: "s-5", Key: "PLAIN", Value: agentConfigValue, Path: "/", Type: "config"},
	}
	for _, args := range [][]string{
		{"secrets", "export", "--app-id", "app-orders", "--path", "", "--format", "kv"},
		{"secrets", "export", "DUP", "DSN", "ODD", "PLAIN", "--app-id", "app-orders", "--path", "", "--format", "kv"},
	} {
		stdout, stderr, err := runPhaseCommand(t, "", args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if strings.Contains(stdout, agentSecretValue) || strings.Contains(stdout, agentSealedValue) ||
			strings.Contains(stdout, "resolved-reference") || !strings.Contains(stdout, "DSN=[REDACTED]") ||
			!strings.Contains(stdout, "PLAIN="+agentConfigValue) {
			t.Fatalf("%v printed:\n%s", args, stdout)
		}
		if strings.Count(stderr, "reference other secrets") != 1 {
			t.Fatalf("%v stderr = %q", args, stderr)
		}
	}
	// Nothing masked for a reference, nothing said.
	console.environments["app-orders/development"] = []consoleSecret{{ID: "s-5", Key: "PLAIN", Value: agentConfigValue, Path: "/", Type: "config"}}
	if _, stderr, err := runPhaseCommand(t, "", "secrets", "export", "--app-id", "app-orders"); err != nil || strings.Contains(stderr, "reference") {
		t.Fatalf("plain export: %q %v", stderr, err)
	}
}

func TestAgentSecretsWrites(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)

	stdout, stderr, err := runPhaseCommand(t, "", "secrets", "create", "new_token", "--app-id", "app-orders", "--random", "hex", "--length", "16", "--type", "sealed")
	if err != nil {
		t.Fatalf("create: %v %s", err, stderr)
	}
	calls := secretsCalls(console.takeCalls())
	if len(calls) != 2 || calls[0].method != "POST" || calls[1].method != "GET" {
		t.Fatalf("create calls = %+v", calls)
	}
	var created struct {
		Secrets []map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(calls[0].body), &created); err != nil || len(created.Secrets) != 1 ||
		created.Secrets[0]["key"] != "NEW_TOKEN" || len(created.Secrets[0]["value"]) != 16 ||
		created.Secrets[0]["path"] != "/" || created.Secrets[0]["type"] != "sealed" {
		t.Fatalf("create body = %s", calls[0].body)
	}
	if !strings.Contains(stdout, "NEW_TOKEN") || strings.Contains(stdout, created.Secrets[0]["value"]) {
		t.Fatalf("create output = %s", stdout)
	}

	if _, _, err := runPhaseCommand(t, "info", "secrets", "create", "LOG_LEVEL", "--app-id", "app-orders", "--type", "config", "--path", "/backend"); err != nil {
		t.Fatal(err)
	}
	calls = secretsCalls(console.takeCalls())
	if len(calls) != 2 || !strings.Contains(calls[0].body, `"value":"info"`) || !strings.Contains(calls[0].body, `"path":"/backend"`) ||
		calls[1].query.Get("path") != "/backend" {
		t.Fatalf("create from stdin calls = %+v", calls)
	}

	// Update finds the secret's ID by key, then writes only what changes.
	stdout, _, err = runPhaseCommand(t, "debug", "secrets", "update", "config_key", "--app-id", "app-orders")
	if err != nil || !strings.Contains(stdout, "Successfully updated the secret") {
		t.Fatalf("update = %s (%v)", stdout, err)
	}
	calls = secretsCalls(console.takeCalls())
	if len(calls) != 3 || calls[0].method != "GET" || calls[0].query.Get("key") != "CONFIG_KEY" || calls[0].query.Get("raw") != "true" ||
		calls[0].query.Get("path") != "/" || calls[1].method != "PUT" || calls[1].body != `{"secrets":[{"id":"s-config","value":"debug"}]}` {
		t.Fatalf("update calls = %+v", calls)
	}
	if _, _, err := runPhaseCommand(t, "", "secrets", "update", "CONFIG_KEY", "--app-id", "app-orders", "--updated-path", "/moved", "--type", "secret"); err != nil {
		t.Fatal(err)
	}
	calls = secretsCalls(console.takeCalls())
	if len(calls) != 3 || calls[1].body != `{"secrets":[{"id":"s-config","path":"/moved","type":"secret"}]}` || calls[2].query.Get("path") != "/moved" {
		t.Fatalf("update path and type calls = %+v", calls)
	}
	// A key that is not there gets the message other logins get.
	stdout, _, err = runPhaseCommand(t, "x", "secrets", "update", "MISSING", "--app-id", "app-orders")
	if err != nil || strings.TrimSpace(stdout) != "secret 'MISSING' not found in path '/'" {
		t.Fatalf("update of a missing key = %q (%v)", stdout, err)
	}
	if calls = secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].method != "GET" {
		t.Fatalf("update of a missing key wrote: %+v", calls)
	}

	stdout, stderr, err = runPhaseCommand(t, "", "secrets", "delete", "api_key", "missing_key", "--app-id", "app-orders")
	if err != nil || !strings.Contains(stderr, "The following keys were not found: MISSING_KEY") {
		t.Fatalf("delete = %s / %s (%v)", stdout, stderr, err)
	}
	calls = secretsCalls(console.takeCalls())
	if len(calls) != 3 || calls[0].query.Get("raw") != "true" || calls[1].method != "DELETE" || calls[1].body != `{"secrets":["s-api"]}` {
		t.Fatalf("delete calls = %+v", calls)
	}
	stdout, _, err = runPhaseCommand(t, "", "secrets", "delete", "NESTED_KEY", "--app-id", "app-orders", "--path", "")
	if err != nil || !strings.Contains(stdout, "Successfully deleted the secrets") {
		t.Fatalf("delete from all paths = %s (%v)", stdout, err)
	}
	if calls = secretsCalls(console.takeCalls()); len(calls) != 3 || calls[0].query.Has("path") || calls[1].body != `{"secrets":["s-nested"]}` {
		t.Fatalf("delete from all paths calls = %+v", calls)
	}

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("FIRST=one\nSECOND=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = runPhaseCommand(t, "", "secrets", "import", envFile, "--app-id", "app-orders", "--env", "staging", "--type", "config")
	if err != nil || !strings.Contains(stdout, "Successfully imported and encrypted 2 secrets") {
		t.Fatalf("import = %s (%v)", stdout, err)
	}
	calls = secretsCalls(console.takeCalls())
	if len(calls) != 1 || calls[0].method != "POST" || calls[0].query.Get("env") != "Staging" ||
		calls[0].body != `{"secrets":[{"key":"FIRST","value":"one","path":"/","type":"config"},{"key":"SECOND","value":"two","path":"/","type":"config"}]}` {
		t.Fatalf("import calls = %+v", calls)
	}
}

func TestAgentSecretsPrintConsoleRefusals(t *testing.T) {
	tests := []struct {
		name, response string
		status         int
		headers        http.Header
		want           []string
		wantRequest    bool
	}{
		{name: "invalid token", status: 401, response: `{"error":"The Agent token is not valid.","code":"invalid_token"}`, want: []string{"The Agent token is not valid."}},
		{name: "grant missing", status: 403, wantRequest: true,
			response: `{"error":"This Workflow has no access to orders-service in Development.","code":"agent_grant_missing","request":{"kind":"setup","title":"Read secrets in orders-service (Development)","action":{"type":"agent_connection.app_access","version":1,"appId":"app-orders","environments":["Development"],"access":"read"}}}`,
			want:     []string{"This Workflow has no access to orders-service in Development.", `"type":"agent_connection.app_access"`}},
		{name: "grant expired", status: 403, wantRequest: true,
			response: `{"error":"Access to orders-service secrets ended.","code":"agent_grant_expired","request":{"kind":"access_change","title":"Renew access to orders-service secrets","action":{"type":"agent_grant.renew","version":1,"connectionId":"connection-orders"}}}`,
			want:     []string{"Access to orders-service secrets ended.", `"type":"agent_grant.renew"`}},
		{name: "access ask", status: 403, wantRequest: true,
			response: `{"error":"Writing secrets needs a member's approval.","code":"agent_access_ask","request":{"kind":"access_change","title":"Create, update and delete secrets","action":{"type":"agent_grant.allow","version":1,"connectionId":"connection-orders","allow":{"classes":["create","update","delete"]}}}}`,
			want:     []string{"Writing secrets needs a member's approval.", `"classes":["create","update","delete"]`}},
		{name: "access blocked", status: 403,
			response: `{"error":"Reading secrets is blocked by the rules of orders-service secrets.","code":"agent_access_blocked","connectionName":"orders-service secrets","class":"read"}`,
			want:     []string{"Reading secrets is blocked by the rules of orders-service secrets.", "A blocked call cannot be requested; tell the human if the task needs it."}},
		{name: "dynamic unsupported", status: 403, response: `{"error":"Dynamic secrets are not available to Agents yet.","code":"agent_dynamic_unsupported"}`,
			want: []string{"Dynamic secrets are not available to Agents yet."}},
		{name: "server-side encryption required", status: 409,
			response: `{"error":"This app does not have server-side encryption enabled, which Agent access needs. A member can enable it in the app's settings.","code":"sse_required"}`,
			want:     []string{"server-side encryption enabled, which Agent access needs"}},
		{name: "environment not found", status: 404, response: `{"error":"Environment 'Development' not found in App app-orders","code":"environment_not_found"}`,
			want: []string{"Environment 'Development' not found in App app-orders"}},
		{name: "rate limited", status: 429, headers: http.Header{"Retry-After": {"7"}}, response: `{"detail":"Request was throttled."}`,
			want: []string{"Request was throttled. Retry after 7 seconds."}},
	}
	for _, test := range tests {
		for _, session := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s in session %t", test.name, session), func(t *testing.T) {
				console := newFakeAgentConsole(t)
				isolateAgentCommand(t, console.server.URL)
				if session {
					t.Setenv("PHASE_AI_ENABLED", "1")
				}
				console.fail = func(*http.Request) (int, string, http.Header) {
					return test.status, `{"value":"` + agentSecretValue + `",` + strings.TrimPrefix(test.response, "{"), test.headers
				}
				stdout, _, err := runPhaseCommand(t, "", "secrets", "list", "--app-id", "app-orders")
				if err == nil {
					t.Fatalf("refusal passed: %s", stdout)
				}
				message := err.Error()
				for _, want := range test.want {
					if !strings.Contains(message, want) {
						t.Fatalf("refusal lacks %q:\n%s", want, message)
					}
				}
				if strings.Contains(message, agentSecretValue) || strings.Contains(stdout, agentSecretValue) {
					t.Fatalf("a refusal carried a secret value:\n%s", message)
				}
				sendLine := "send this JSON unchanged to POST http://phase.invalid/v1/requests"
				switch {
				case !test.wantRequest:
					if strings.Contains(message, "phase.invalid") {
						t.Fatalf("a refusal without a request said how to send one:\n%s", message)
					}
				case session:
					if !strings.Contains(message, "To ask a member for it, "+sendLine) || strings.Contains(message, "filed from inside") {
						t.Fatalf("in-session refusal:\n%s", message)
					}
				default:
					if !strings.Contains(message, "filed from inside a Phase AI session") || !strings.Contains(message, sendLine) {
						t.Fatalf("out-of-session refusal:\n%s", message)
					}
				}
				if test.wantRequest {
					lines := strings.Split(message, "\n")
					var request map[string]any
					if err := json.Unmarshal([]byte(lines[len(lines)-1]), &request); err != nil || request["kind"] == nil {
						t.Fatalf("the request is not the last line as JSON:\n%s", message)
					}
				}
			})
		}
	}
}

// An app or environment the Workflow cannot use is still asked for, so the
// Agent sees the Console's refusal and its ready-to-send request. Only an app
// named by a name nothing matches cannot be sent; that refusal names the app.
func TestAgentSecretsOutsideTheGrantedApps(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)

	_, _, err := runPhaseCommand(t, "", "secrets", "list", "--app-id", "app-unknown", "--env", "production")
	if err == nil || !strings.Contains(err.Error(), `"appId":"app-unknown"`) {
		t.Fatalf("unknown app ID: %v", err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Get("app_id") != "app-unknown" || calls[0].query.Get("env") != "production" {
		t.Fatalf("unknown app ID calls = %+v", calls)
	}
	_, _, err = runPhaseCommand(t, "", "secrets", "get", "API_KEY", "--app-id", "app-orders", "--env", "production")
	if err == nil || !strings.Contains(err.Error(), `"environments":["production"]`) {
		t.Fatalf("ungranted environment: %v", err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 {
		t.Fatalf("ungranted environment calls = %+v", calls)
	}
	_, _, err = runPhaseCommand(t, "", "secrets", "create", "X", "--app", "billing", "--env", "production", "--random", "hex")
	if err == nil || !strings.Contains(err.Error(), `No app named "billing"`) || !strings.Contains(err.Error(), `apps it can use: "orders-service"`) || !strings.Contains(err.Error(), "must be the app's exact name") ||
		strings.Contains(err.Error(), "contains") ||
		!strings.Contains(err.Error(), `"appName":"billing"`) || !strings.Contains(err.Error(), `"access":"read_write"`) {
		t.Fatalf("unknown app name: %v", err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 0 {
		t.Fatalf("an unknown app name reached the secrets API: %+v", calls)
	}
}

func TestAgentAppsListAndInit(t *testing.T) {
	console := newFakeAgentConsole(t)
	work := isolateAgentCommand(t, console.server.URL)

	stdout, _, err := runPhaseCommand(t, "", "apps", "list")
	if err != nil {
		t.Fatal(err)
	}
	var apps []appListEntry
	if err := json.Unmarshal([]byte(stdout), &apps); err != nil || len(apps) != 1 || apps[0].ID != "app-orders" ||
		apps[0].Name != "orders-service" || len(apps[0].Environments) != 2 || apps[0].Environments[0] != (envListEntry{ID: "env-dev", Name: "Development", EnvType: "DEV"}) {
		t.Fatalf("apps list = %s (%v)", stdout, err)
	}
	stdout, _, err = runPhaseCommand(t, "", "init", "--app-id", "app-orders", "--env", "staging")
	if err != nil || !strings.Contains(stdout, "Initialization completed successfully") {
		t.Fatalf("init = %s (%v)", stdout, err)
	}
	written, err := os.ReadFile(filepath.Join(work, ".phase.json"))
	var phaseJSON config.PhaseJSONConfig
	if err != nil || json.Unmarshal(written, &phaseJSON) != nil || phaseJSON.AppID != "app-orders" || phaseJSON.DefaultEnv != "Staging" ||
		phaseJSON.EnvID != "env-staging" || phaseJSON.PhaseApp != "orders-service" {
		t.Fatalf(".phase.json = %s (%v)", written, err)
	}
	console.takeCalls()
	// The commands now pick the app and environment up from .phase.json.
	if _, _, err := runPhaseCommand(t, "", "secrets", "list"); err != nil {
		t.Fatal(err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Get("app_id") != "app-orders" || calls[0].query.Get("env") != "Staging" {
		t.Fatalf("list from .phase.json calls = %+v", calls)
	}
}

func TestAgentRefusesWhatItCannotUse(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"secrets", "create", "KEY", "--override", "--app-id", "app-orders"}, "Personal overrides are not available to an Agent login."},
		{[]string{"secrets", "update", "KEY", "--override", "--app-id", "app-orders"}, "Personal overrides are not available to an Agent login."},
		{[]string{"secrets", "update", "KEY", "--toggle-override", "--app-id", "app-orders"}, "Personal overrides are not available to an Agent login."},
		{[]string{"shell", "--app-id", "app-orders"}, "phase shell is not available to an Agent login. Use phase run <command> instead."},
		{[]string{"dynamic-secrets", "list", "--app-id", "app-orders"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"dynamic-secrets", "lease", "generate", "secret-id"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"secrets", "list", "--app-id", "app-orders", "--lease-ttl", "60"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"secrets", "list", "--app-id", "app-orders", "--generate-leases", "true"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"secrets", "get", "API_KEY", "--app-id", "app-orders", "--generate-leases", "false"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"secrets", "export", "--app-id", "app-orders", "--lease-ttl", "60"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"run", "--app-id", "app-orders", "--generate-leases", "true", "--", "true"}, "Dynamic secrets are not available to Agents yet."},
		{[]string{"run", "--app-id", "app-orders", "--lease-ttl", "60", "--", "true"}, "Dynamic secrets are not available to Agents yet."},
	}
	for _, test := range tests {
		_, _, err := runPhaseCommand(t, "", test.args...)
		if err == nil || err.Error() != test.want {
			t.Fatalf("phase %s: %v, want %q", strings.Join(test.args, " "), err, test.want)
		}
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 0 {
		t.Fatalf("a refused command reached the secrets API: %+v", calls)
	}

	t.Setenv("PHASE_OFFLINE", "1")
	for _, args := range [][]string{{"secrets", "list", "--app-id", "app-orders"}, {"run", "--app-id", "app-orders", "--", "true"}, {"apps", "list"}} {
		_, _, err := runPhaseCommand(t, "", args...)
		if err == nil || !strings.HasPrefix(err.Error(), "Offline mode is not available to an Agent login") {
			t.Fatalf("phase %s offline: %v", strings.Join(args, " "), err)
		}
	}
	if calls := console.takeCalls(); len(calls) != 0 {
		t.Fatalf("offline mode reached the Console: %+v", calls)
	}
}

// Masking does not depend on a harness being detected: an Agent login is the
// AI tool by definition.
func TestAgentOutputIsMaskedWithAndWithoutAHarness(t *testing.T) {
	for _, harness := range []string{"", "CLAUDECODE"} {
		t.Run("harness "+harness, func(t *testing.T) {
			console := newFakeAgentConsole(t)
			isolateAgentCommand(t, console.server.URL)
			if harness != "" {
				t.Setenv(harness, "1")
			}
			for _, args := range [][]string{
				{"secrets", "list", "--app-id", "app-orders", "--show"},
				{"secrets", "get", "API_KEY", "SIGNING_KEY", "CONFIG_KEY", "--app-id", "app-orders"},
				{"secrets", "export", "--app-id", "app-orders"},
			} {
				stdout, stderr, err := runPhaseCommand(t, "", args...)
				if err != nil {
					t.Fatalf("%v: %v", args, err)
				}
				if strings.Contains(stdout+stderr, agentSecretValue) || strings.Contains(stdout+stderr, agentSealedValue) ||
					!strings.Contains(stdout, "[REDACTED]") || !strings.Contains(stdout, agentConfigValue) {
					t.Fatalf("%v output:\n%s", args, stdout)
				}
			}
			// The run blocklist applies as well.
			_, _, err := runPhaseCommand(t, "", "run", "--app-id", "app-orders", "--", "printenv")
			if err == nil || !strings.Contains(err.Error(), "is blocked in AI mode") {
				t.Fatalf("printenv under an Agent login: %v", err)
			}
		})
	}
}

func TestAgentRunInjectsAndKeepsSessionVariables(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.environments["app-orders/development"] = append(console.environments["app-orders/development"],
		consoleSecret{ID: "s-aws", Key: "AWS_SECRET_ACCESS_KEY", Value: "live-aws-from-app", Path: "/", Type: "secret"},
		consoleSecret{ID: "s-proxy", Key: "HTTPS_PROXY", Value: "http://app-secret-proxy.invalid:1", Path: "/", Type: "config"},
		consoleSecret{ID: "s-ai", Key: "PHASE_AI_PROXY_URL", Value: "http://app-secret-control.invalid", Path: "/", Type: "config"},
	)
	command := `printf '%s|%s|%s|%s' "$CONFIG_KEY" "$REF_KEY" "$AWS_SECRET_ACCESS_KEY" "$HTTPS_PROXY$PHASE_AI_PROXY_URL"`

	t.Setenv("AWS_SECRET_ACCESS_KEY", "decoy-from-the-session")
	stdout, stderr, err := runPhaseCommand(t, "", "run", "--app-id", "app-orders", "--", command)
	if err != nil {
		t.Fatalf("run outside a session: %v %s", err, stderr)
	}
	parts := strings.Split(stdout, "|")
	if len(parts) != 4 || parts[0] != agentConfigValue || parts[1] != "resolved-reference" || parts[2] != "live-aws-from-app" ||
		!strings.Contains(parts[3], "app-secret-proxy") || strings.Contains(stderr, "did not inject") {
		t.Fatalf("outside a session: stdout=%q stderr=%q", stdout, stderr)
	}
	runCalls := secretsCalls(console.takeCalls())
	if len(runCalls) != 1 || runCalls[0].query.Has("raw") || runCalls[0].query.Get("path") != "/" || runCalls[0].query.Has("dynamic") {
		t.Fatalf("run calls = %+v", runCalls)
	}

	t.Setenv("PHASE_AI_ENABLED", "1")
	t.Setenv(phaseproxy.ReservedEnvironmentKey, strings.Join(providerrulestest.CredentialEnvironment("aws"), ","))
	stdout, stderr, err = runPhaseCommand(t, "", "run", "--app-id", "app-orders", "--", command)
	if err != nil {
		t.Fatalf("run inside a session: %v %s", err, stderr)
	}
	parts = strings.Split(stdout, "|")
	if len(parts) != 4 || parts[0] != agentConfigValue || parts[2] != "decoy-from-the-session" ||
		strings.Contains(parts[3], "app-secret") {
		t.Fatalf("inside a session: stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "Phase: did not inject AWS_SECRET_ACCESS_KEY, HTTPS_PROXY, PHASE_AI_PROXY_URL: the Phase AI session reserves these names") ||
		!strings.Contains(stderr, "Injected") {
		t.Fatalf("inside a session stderr = %q", stderr)
	}
	if strings.Contains(stderr, "live-aws-from-app") {
		t.Fatalf("the skipped line carried a value: %q", stderr)
	}
}

func TestSkipReservedSessionVariablesOnlyInsideASession(t *testing.T) {
	secrets := func() map[string]string {
		return map[string]string{"HTTPS_PROXY": "x", "https_proxy": "x", "GITHUB_TOKEN": "x", "PHASE_AGENT_TOKEN": "x", "SSL_CERT_FILE": "x", "APP_SETTING": "x"}
	}
	t.Setenv("PHASE_AI_ENABLED", "")
	outside := secrets()
	if skipped := skipReservedSessionVariables(outside); skipped != nil || len(outside) != 6 {
		t.Fatalf("outside a session skipped %v", skipped)
	}
	t.Setenv("PHASE_AI_ENABLED", "1")
	// As a session with an AWS and a GitHub Connection exports it.
	t.Setenv(phaseproxy.ReservedEnvironmentKey, strings.Join(providerrulestest.CredentialEnvironment("aws", "github"), ","))
	inside := secrets()
	skipped := skipReservedSessionVariables(inside)
	want := []string{"GITHUB_TOKEN", "HTTPS_PROXY", "PHASE_AGENT_TOKEN", "SSL_CERT_FILE", "https_proxy"}
	sort.Strings(want)
	if strings.Join(skipped, ",") != strings.Join(want, ",") || len(inside) != 1 || inside["APP_SETTING"] != "x" {
		t.Fatalf("inside a session skipped %v, kept %v", skipped, inside)
	}
}

// A stored Agent login works the same as one in PHASE_SERVICE_TOKEN and leaves
// nothing behind: no offline cache, no user data file.
func TestAgentLoginFromTheKeyringWritesNothingToDisk(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	t.Setenv("PHASE_HOST", "")
	gokeyring.MockInit()
	const accountID = "agent-0123456789abcdef01234567"
	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: accountID, PrincipalType: config.PrincipalAgent, PrincipalName: "Deploy bot"}); err != nil {
		t.Fatal(err)
	}
	if err := gokeyring.Set("phase-cli-user-"+accountID, "pss", agentTestToken()); err != nil {
		t.Fatal(err)
	}
	before := listFiles(t, filepath.Dir(config.PhaseSecretsDir))
	for _, args := range [][]string{
		{"secrets", "list", "--app-id", "app-orders"},
		{"secrets", "get", "API_KEY", "--app-id", "app-orders"},
		{"secrets", "export", "--app-id", "app-orders"},
		{"run", "--app-id", "app-orders", "--", "true"},
		{"apps", "list"},
	} {
		if _, stderr, err := runPhaseCommand(t, "", args...); err != nil {
			t.Fatalf("%v: %v %s", args, err, stderr)
		}
	}
	// Export reads the listing twice: resolved, and unresolved to find references.
	if len(secretsCalls(console.takeCalls())) != 5 {
		t.Fatal("the stored Agent login did not reach the secrets API")
	}
	if after := listFiles(t, filepath.Dir(config.PhaseSecretsDir)); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("an Agent login wrote to disk:\nbefore %v\nafter  %v", before, after)
	}
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files
}

// Personal and service tokens keep the SDK path: the same routes, the same
// Authorization, nothing from the Agent API.
func TestPersonalAndServiceTokensKeepTheSDKPath(t *testing.T) {
	for _, test := range []struct{ token, authorization string }{
		{"pss_user:v1:" + strings.Repeat("e", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64), "Bearer User " + strings.Repeat("e", 64)},
		{"pss_service:v2:" + strings.Repeat("e", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64), "Bearer ServiceAccount " + strings.Repeat("e", 64)},
	} {
		var mu sync.Mutex
		var routes []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			routes = append(routes, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
			mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"stop here"}`))
		}))
		isolateAgentCommand(t, server.URL)
		t.Setenv("PHASE_SERVICE_TOKEN", test.token)
		for _, args := range [][]string{
			{"secrets", "list", "--app-id", "app-orders"},
			{"secrets", "export", "--app-id", "app-orders"},
			{"run", "--app-id", "app-orders", "--", "true"},
			{"apps", "list"},
			{"init", "--app-id", "app-orders", "--env", "dev"},
		} {
			if _, _, err := runPhaseCommand(t, "", args...); err == nil {
				t.Fatalf("%v succeeded against a refusing Console", args)
			}
		}
		server.Close()
		if ai.AgentLogin() {
			t.Fatal("a personal or service token was treated as an Agent login")
		}
		if len(routes) != 5 {
			t.Fatalf("routes = %v", routes)
		}
		for _, route := range routes {
			if route != "GET /service/secrets/tokens/ "+test.authorization {
				t.Fatalf("route = %q", route)
			}
		}
	}
}

func TestAIStatusListsAppConnections(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	withAICAKeystore(t, gokeyring.ErrNotFound)
	originalAIConfig, originalConfig := config.AIConfigPath, config.ConfigFilePath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.AIConfigPath, config.ConfigFilePath = originalAIConfig, originalConfig })
	if err := config.SaveAIConfig(&config.AIConfig{Enabled: true, HarnessIDs: []string{"claude-code"}}); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://phase.invalid/v1/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[` +
			`{"connectionId":"aws-1","name":"aws-prod","serviceType":"aws","protocol":"http","credentialId":"c","credentialProvider":"aws","state":"ready"},` +
			`{"connectionId":"c-orders","name":"orders-service secrets","serviceType":"phase_app","credentialId":"","credentialProvider":"","protocol":"","state":"active",` +
			`"app":{"id":"app-orders","name":"orders-service"},"environments":[{"id":"e1","name":"Development","envType":"dev"},{"id":"e2","name":"Staging","envType":"staging"}],` +
			`"access":{"read":{"effect":"allow"},"create":{"effect":"allow","until":"2026-11-17T12:00:00Z"},"update":{"effect":"ask"},"delete":{"effect":"block"}}},` +
			`{"connectionId":"c-billing","name":"billing secrets","serviceType":"phase_app","credentialId":"","credentialProvider":"","protocol":"","state":"expired","stateReason":"access_expired",` +
			`"app":{"id":"app-billing","name":"billing"},"environments":[{"id":"e3","name":"Production","envType":"prod"}],"access":{}}]}`))
	}))
	t.Cleanup(proxy.Close)
	parsed, _ := url.Parse(proxy.URL)
	parsed.User = url.UserPassword("phase", "runtime-capability")
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: parsed.String(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, testRuntimeEnvironmentPlan(), nil, true); err != nil {
		t.Fatal(err)
	}
	status := renderAIStatus(context.Background())
	for _, required := range []string{
		"Connections: aws-prod (aws): ready\n",
		"             orders-service secrets (phase_app): active; orders-service (Development, Staging): read, create until 2026-11-17 12:00Z allowed; update ask; delete blocked\n",
		"             billing secrets (phase_app): expired; billing (Production)\n",
	} {
		if !strings.Contains(status, required) {
			t.Fatalf("status missing %q:\n%s", required, status)
		}
	}
}

const expiredBillingAccess = `{"schemaVersion":1,"apps":[],"expired":[{"connectionId":"connection-billing","connectionName":"billing secrets",` +
	`"app":{"id":"app-billing","name":"billing"},"expiredAt":"2026-11-01T00:00:00Z"}]}`

// A name that matches only an expired grant is sent by app ID, so the Agent
// gets the Console's refusal and its renew request.
func TestAgentAppNameResolvesAnExpiredGrant(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.appAccess = expiredBillingAccess
	console.fail = func(r *http.Request) (int, string, http.Header) {
		return http.StatusForbidden, `{"error":"Access to billing secrets ended.","code":"agent_grant_expired","request":{"kind":"access_change","title":"Renew access to billing secrets","action":{"type":"agent_grant.renew","version":1,"connectionId":"connection-billing"}}}`, nil
	}
	_, _, err := runPhaseCommand(t, "", "secrets", "list", "--app", "billing", "--env", "production")
	if err == nil || !strings.Contains(err.Error(), "Access to billing secrets ended.") || !strings.Contains(err.Error(), `"type":"agent_grant.renew"`) {
		t.Fatalf("expired app by name: %v", err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 1 || calls[0].query.Get("app_id") != "app-billing" {
		t.Fatalf("expired app by name calls = %+v", calls)
	}
}

func TestAgentAppsListExplainsExpiredAndMissingAccess(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.appAccess = expiredBillingAccess
	_, stderr, err := runPhaseCommand(t, "", "apps", "list")
	if err != nil || !strings.Contains(stderr, "Access to billing (app-billing) through billing secrets expired at 2026-11-01T00:00:00Z.") ||
		!strings.Contains(stderr, `{"action":{"connectionId":"connection-billing","type":"agent_grant.renew","version":1},"kind":"access_change","title":"Renew access to billing secrets"}`) {
		t.Fatalf("apps list with expired access: err=%v stderr=%q", err, stderr)
	}

	console = newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	console.appAccess = `{"schemaVersion":1,"apps":[],"expired":[]}`
	_, _, err = runPhaseCommand(t, "", "apps", "list")
	if err == nil || err.Error() != phase.NoAppAccessMessage || !strings.Contains(err.Error(), "phase ai guide app-secrets") {
		t.Fatalf("apps list without access: %v", err)
	}
}

// Inside a session that did not export its reserved names, phase run would
// inject everything; it refuses instead.
func TestRunRefusesASessionWithoutReservedNames(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	t.Setenv("PHASE_AI_ENABLED", "1")
	t.Setenv(phaseproxy.ReservedEnvironmentKey, "")
	if err := os.Unsetenv(phaseproxy.ReservedEnvironmentKey); err != nil {
		t.Fatal(err)
	}
	_, _, err := runPhaseCommand(t, "", "run", "--app-id", "app-orders", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "did not provide its reserved names") {
		t.Fatalf("run without reserved names: %v", err)
	}
	if calls := secretsCalls(console.takeCalls()); len(calls) != 0 {
		t.Fatalf("run fetched secrets it could not filter: %+v", calls)
	}
	// Present but empty is a session with no provider credentials: it runs.
	t.Setenv(phaseproxy.ReservedEnvironmentKey, "")
	if _, stderr, err := runPhaseCommand(t, "", "run", "--app-id", "app-orders", "--", "true"); err != nil {
		t.Fatalf("run with an empty reserved list: %v %s", err, stderr)
	}
}
