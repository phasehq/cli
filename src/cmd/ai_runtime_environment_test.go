package cmd

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/aiproxy"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func testRuntimeEnvironmentPlan() phaseproxy.ProcessEnvironmentPlan {
	return phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{
			"PHASE_AI_ENABLED":      "1",
			"PHASE_AI_CA_BUNDLE":    "/home/dev/.phase/ai/ca-bundle.pem",
			"HTTPS_PROXY":           "http://phase:capability@127.0.0.1:9543",
			"https_proxy":           "http://phase:capability@127.0.0.1:9543",
			"NO_PROXY":              "127.0.0.1,localhost,::1",
			"AWS_CA_BUNDLE":         "/home/dev/.phase/ai/ca-bundle.pem",
			"NODE_EXTRA_CA_CERTS":   "/home/dev/.phase/ai/ca-bundle.pem",
			"AWS_ACCESS_KEY_ID":     "AKIADECOY",
			"AWS_SECRET_ACCESS_KEY": "decoy'with'quotes",
			"PGHOST":                "127.0.0.1",
			"PGPORT":                "9544",
			"PGPASSWORD":            "pg-decoy",
			"PGSSLMODE":             "verify-full",
			"PGSSLROOTCERT":         "/home/dev/.phase/ai/ca-bundle.pem",
		},
		Unset: []string{"PHASE_SERVICE_TOKEN", "AWS_PROFILE"},
	}
}

func withRuntimeEnvironmentGOOS(t *testing.T, goos string) {
	t.Helper()
	previous := runtimeEnvironmentGOOS
	runtimeEnvironmentGOOS = goos
	t.Cleanup(func() { runtimeEnvironmentGOOS = previous })
}

func TestRenderRuntimeEnvironmentSeparatesRoutingFromDecoys(t *testing.T) {
	withRuntimeEnvironmentGOOS(t, "linux")
	content, err := renderRuntimeEnvironment(4242, testRuntimeEnvironmentPlan(), true)
	if err != nil {
		t.Fatal(err)
	}
	begin := strings.Index(content, "if kill -0 4242 2>/dev/null; then\n")
	end := strings.Index(content, "\nfi\n")
	if begin < 0 || end < begin {
		t.Fatalf("missing liveness guard:\n%s", content)
	}
	guarded, outside := content[begin:end], content[:begin]+content[end:]
	for _, key := range []string{"PHASE_AI_ENABLED", "PHASE_AI_CA_BUNDLE", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PGSSLROOTCERT"} {
		if !strings.Contains(guarded, "  export "+key+"=") {
			t.Fatalf("%s must be exported only while the proxy is alive:\n%s", key, content)
		}
		if strings.Contains(outside, "export "+key+"=") {
			t.Fatalf("%s leaked outside the liveness guard:\n%s", key, content)
		}
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PGHOST", "PGPORT", "PGPASSWORD", "PGSSLMODE"} {
		if !strings.Contains(outside, "\nexport "+key+"=") {
			t.Fatalf("%s must stay exported when the proxy is gone:\n%s", key, content)
		}
		if strings.Contains(guarded, "export "+key+"=") {
			t.Fatalf("%s must not depend on the proxy:\n%s", key, content)
		}
	}
	if !strings.Contains(content, "\nunset AWS_PROFILE PHASE_SERVICE_TOKEN\n") {
		t.Fatalf("explicit unsets missing:\n%s", content)
	}
	if !strings.Contains(content, `export AWS_SECRET_ACCESS_KEY='decoy'"'"'with'"'"'quotes'`) {
		t.Fatalf("values must be single-quoted for POSIX sh:\n%s", content)
	}
	if !strings.HasSuffix(content, "\n:\n") {
		t.Fatalf("file must end with a successful command:\n%s", content)
	}

	degraded, err := renderRuntimeEnvironment(0, testRuntimeEnvironmentPlan(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(degraded, "kill -0") || strings.Contains(degraded, "PROXY") || strings.Contains(degraded, "PHASE_AI_ENABLED") ||
		!strings.Contains(degraded, "export AWS_ACCESS_KEY_ID='AKIADECOY'") || !strings.Contains(degraded, "export PGHOST='127.0.0.1'") ||
		!strings.Contains(degraded, "proxy is not running") || !strings.HasSuffix(degraded, "\n:\n") {
		t.Fatalf("degraded environment must keep decoys and drop routing:\n%s", degraded)
	}
	if stripped := stripProxyBlock(content); stripped != degraded {
		t.Fatalf("stripping the live file must equal the degraded render:\n--- stripped ---\n%s\n--- degraded ---\n%s", stripped, degraded)
	}
}

func TestRenderRuntimeEnvironmentProbesTheProxyPortOnWindows(t *testing.T) {
	withRuntimeEnvironmentGOOS(t, "windows")
	content, err := renderRuntimeEnvironment(4242, testRuntimeEnvironmentPlan(), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "kill -0") ||
		!strings.Contains(content, proxyBlockBegin+"\nif true 2>/dev/null </dev/tcp/127.0.0.1/9543; then\n") {
		t.Fatalf("Windows liveness guard:\n%s", content)
	}
	unrouted := testRuntimeEnvironmentPlan()
	delete(unrouted.Set, "HTTPS_PROXY")
	delete(unrouted.Set, "https_proxy")
	content, err = renderRuntimeEnvironment(4242, unrouted, true)
	if err != nil || !strings.Contains(content, "\nif false; then\n") {
		t.Fatalf("a plan without a proxy must never route: err=%v\n%s", err, content)
	}
	for name, proxy := range map[string]string{
		"hostname": "http://phase:capability@localhost:9543",
		"IPv6":     "http://phase:capability@[::1]:9543",
		"no port":  "http://phase:capability@127.0.0.1",
		"bad port": "http://phase:capability@127.0.0.1:99999",
	} {
		plan := testRuntimeEnvironmentPlan()
		plan.Set["HTTPS_PROXY"] = proxy
		if _, err := renderRuntimeEnvironment(4242, plan, true); err == nil {
			t.Fatalf("%s proxy was accepted", name)
		}
	}
}

func TestRenderRuntimeEnvironmentJSONSplitsRoutingFromDecoys(t *testing.T) {
	payload, err := renderRuntimeEnvironmentJSON(4242, testRuntimeEnvironmentPlan(), true)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Schema != runtimeEnvironmentSchema || payload.PID != 4242 || !payload.ProxyLive {
		t.Fatalf("unexpected payload header: %+v", payload)
	}
	for _, key := range []string{"PHASE_AI_ENABLED", "PHASE_AI_CA_BUNDLE", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PGSSLROOTCERT"} {
		if _, ok := payload.Proxy[key]; !ok {
			t.Fatalf("%s must be a proxy-only key: %+v", key, payload)
		}
		if _, ok := payload.Set[key]; ok {
			t.Fatalf("%s leaked into the always-set keys", key)
		}
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PGHOST", "PGPORT", "PGPASSWORD", "PGSSLMODE"} {
		if _, ok := payload.Set[key]; !ok {
			t.Fatalf("%s must stay set when the proxy is gone: %+v", key, payload)
		}
	}
	if strings.Join(payload.Unset, ",") != "AWS_PROFILE,PHASE_SERVICE_TOKEN" {
		t.Fatalf("unset = %v", payload.Unset)
	}
	degraded, err := renderRuntimeEnvironmentJSON(0, testRuntimeEnvironmentPlan(), false)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.ProxyLive || len(degraded.Proxy) != 0 || degraded.Set["AWS_ACCESS_KEY_ID"] != "AKIADECOY" {
		t.Fatalf("degraded payload must keep decoys and drop routing: %+v", degraded)
	}
	if _, err := renderRuntimeEnvironmentJSON(0, testRuntimeEnvironmentPlan(), true); err == nil {
		t.Fatal("live payload without a PID was accepted")
	}
}

func TestRenderRuntimeEnvironmentRejectsUnsafeInput(t *testing.T) {
	if _, err := renderRuntimeEnvironment(0, phaseproxy.ProcessEnvironmentPlan{}, true); err == nil {
		t.Fatal("live environment without a PID was accepted")
	}
	for name, plan := range map[string]phaseproxy.ProcessEnvironmentPlan{
		"newline value": {Set: map[string]string{"AWS_ACCESS_KEY_ID": "a\nb"}},
		"invalid key":   {Set: map[string]string{"AWS-KEY": "a"}},
		"invalid unset": {Unset: []string{"bad key"}},
	} {
		if _, err := renderRuntimeEnvironment(1, plan, true); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestClaudeEnvironmentLoaderIsIdempotentAndNamesOnlyThePath(t *testing.T) {
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	if err := os.WriteFile(loaderPath, []byte("export FOO=bar"), 0o600); err != nil {
		t.Fatal(err)
	}
	environmentPath := filepath.Join(t.TempDir(), "env.sh")
	for i := 0; i < 2; i++ {
		if err := installClaudeEnvironmentLoader(loaderPath, environmentPath); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(loaderPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := "export FOO=bar\n" + claudeEnvironmentLoaderSnippet(environmentPath)
	if string(content) != expected {
		t.Fatalf("loader content:\n%s\nexpected:\n%s", content, expected)
	}
	if !strings.Contains(string(content), `[ "${PHASE_AI_ENABLED:-}" != 1 ]`) {
		t.Fatalf("loader must defer to an inherited phase ai run environment:\n%s", content)
	}
	if err := installClaudeEnvironmentLoader("", environmentPath); err != nil {
		t.Fatalf("missing CLAUDE_ENV_FILE must be a no-op: %v", err)
	}
	if err := installClaudeEnvironmentLoader(loaderPath, "relative/env.sh"); err == nil {
		t.Fatal("relative environment path was accepted")
	}
}

func sourceRuntimeEnvironment(t *testing.T, loaderPath string, extraEnv ...string) string {
	t.Helper()
	script := `. "$1"; status=$?; printf '%s|%s|%s|%s' "${HTTPS_PROXY:-}" "${AWS_ACCESS_KEY_ID:-}" "${PHASE_AI_ENABLED:-}" "$status"`
	command := exec.Command("/bin/sh", "-c", script, "sh", loaderPath)
	command.Env = append([]string{"PATH=/usr/bin:/bin"}, extraEnv...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing failed: %v\n%s", err, output)
	}
	return string(output)
}

func TestRuntimeEnvironmentSourcesInRealShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	directory := t.TempDir()
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	if err := installClaudeEnvironmentLoader(loaderPath, runtimeEnvironmentPath(directory)); err != nil {
		t.Fatal(err)
	}
	plan := testRuntimeEnvironmentPlan()
	if got := sourceRuntimeEnvironment(t, loaderPath); got != "|||0" {
		t.Fatalf("missing environment file must be a silent no-op, got %q", got)
	}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}
	if got := sourceRuntimeEnvironment(t, loaderPath); got != "http://phase:capability@127.0.0.1:9543|AKIADECOY|1|0" {
		t.Fatalf("live proxy environment, got %q", got)
	}
	if got := sourceRuntimeEnvironment(t, loaderPath, "PHASE_AI_ENABLED=1"); got != "||1|0" {
		t.Fatalf("inherited phase ai run environment must win, got %q", got)
	}
	if got := sourceRuntimeEnvironment(t, loaderPath, "PHASE_AI_ENABLED=1", hookRuntimeMarker+"=stale"); got != "http://phase:capability@127.0.0.1:9543|AKIADECOY|1|0" {
		t.Fatalf("an inherited hook daemon environment must be refreshed, got %q", got)
	}
	const deadPID = 1 << 30
	if err := writeRuntimeEnvironment(directory, deadPID, "generation-one", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}
	if got := sourceRuntimeEnvironment(t, loaderPath); got != "|AKIADECOY||0" {
		t.Fatalf("dead proxy must drop routing and keep decoys, got %q", got)
	}
	if err := writeRuntimeEnvironment(directory, 0, "generation-one", time.Time{}, plan, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := sourceRuntimeEnvironment(t, loaderPath); got != "|AKIADECOY||0" {
		t.Fatalf("degraded environment, got %q", got)
	}
}

// findTestBash returns Git Bash on Windows (System32\bash.exe is WSL), else bash.
func findTestBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		candidate := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		if _, err := os.Stat(candidate); err != nil {
			t.Skip("Git Bash is not installed")
		}
		return candidate
	}
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	return path
}

func TestRuntimeEnvironmentWindowsGuardSourcesInBash(t *testing.T) {
	bash := findTestBash(t)
	withRuntimeEnvironmentGOOS(t, "windows")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	proxy := "http://phase:capability@" + listener.Addr().String()
	plan := testRuntimeEnvironmentPlan()
	plan.Set["HTTPS_PROXY"], plan.Set["https_proxy"] = proxy, proxy
	directory := t.TempDir()
	if err := writeRuntimeEnvironment(directory, 4242, "generation-one", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}
	inherited := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTPS_PROXY", "HTTP_PROXY", "PHASE_AI_ENABLED", "AWS_ACCESS_KEY_ID":
			continue
		}
		inherited = append(inherited, entry)
	}
	source := func() string {
		script := `. "$1"; status=$?; printf '%s|%s|%s|%s' "${HTTPS_PROXY:-}" "${AWS_ACCESS_KEY_ID:-}" "${PHASE_AI_ENABLED:-}" "$status"`
		command := exec.Command(bash, "-c", script, "bash", filepath.ToSlash(runtimeEnvironmentPath(directory)))
		command.Env = inherited
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("sourcing failed: %v\n%s", err, output)
		}
		return string(output)
	}
	if got := source(); got != proxy+"|AKIADECOY|1|0" {
		t.Fatalf("live proxy environment, got %q", got)
	}
	listener.Close()
	if got := source(); got != "|AKIADECOY||0" {
		t.Fatalf("stopped proxy must drop routing and keep decoys, got %q", got)
	}
}

func TestWriteRuntimeEnvironmentIsOwnerOnlyAndRemovable(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", time.Now().UTC(), testRuntimeEnvironmentPlan(), connections, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtimeEnvironmentPath(directory), runtimeEnvironmentJSONPath(directory), runtimeEnvironmentStatusPath(directory)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %o", path, info.Mode().Perm())
		}
	}
	var twin runtimeEnvironmentJSON
	if err := readOwnerOnlyJSON(runtimeEnvironmentJSONPath(directory), &twin); err != nil {
		t.Fatal(err)
	}
	if twin.PID != os.Getpid() || !twin.ProxyLive || twin.Proxy["HTTPS_PROXY"] == "" || twin.Set["AWS_ACCESS_KEY_ID"] != "AKIADECOY" {
		t.Fatalf("JSON twin does not mirror the shell file: %+v", twin)
	}
	status, err := os.ReadFile(runtimeEnvironmentStatusPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(status), "capability") || strings.Contains(string(status), "AKIADECOY") || !strings.Contains(string(status), `"aws-prod"`) {
		t.Fatalf("status must be printable and credential-free: %s", status)
	}
	health := inspectHookRuntime(directory)
	if health.ready {
		t.Fatal("no runtime state must not read as ready")
	}
	for i := 0; i < 2; i++ {
		if err := removeRuntimeEnvironmentFiles(); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{runtimeEnvironmentPath(directory), runtimeEnvironmentJSONPath(directory)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived removal: %v", path, err)
		}
	}
}

func TestInspectHookRuntimeAndStatusLines(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	if line := runtimeStatusLine(inspectHookRuntime(directory)); !strings.Contains(line, "proxy unavailable") {
		t.Fatalf("empty directory status = %q", line)
	}
	if err := writeOwnerOnlyJSON(hookRuntimeFailurePath(directory, "generation-one"), hookRuntimeFailure{Generation: "generation-one", Reason: "authentication"}); err != nil {
		t.Fatal(err)
	}
	if line := runtimeStatusLine(inspectHookRuntime(directory)); !strings.Contains(line, "phase auth --mode token") {
		t.Fatalf("authentication failure status = %q", line)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: "generation-two", PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if line := runtimeStatusLine(inspectHookRuntime(directory)); !strings.Contains(line, "proxy is starting") {
		t.Fatalf("starting status = %q", line)
	}
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-two", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if line := runtimeStatusLine(inspectHookRuntime(directory)); !strings.Contains(line, "no Connections yet") {
		t.Fatalf("ready without connections status = %q", line)
	}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", ServiceType: "aws", Protocol: "http"}, {ConnectionID: "conn-2", Name: "analytics", ServiceType: "postgres", Protocol: "postgres"}}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-two", state.StartedAt, phaseproxy.ProcessEnvironmentPlan{}, connections, true); err != nil {
		t.Fatal(err)
	}
	line := runtimeStatusLine(inspectHookRuntime(directory))
	if !strings.Contains(line, "conn-1 (aws), analytics (postgres)") || strings.Contains(line, "capability") {
		t.Fatalf("ready status = %q", line)
	}
}

func TestReconcileNeverRetiresAReplacementsRouting(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	plan := testRuntimeEnvironmentPlan()
	const deadPID = 1 << 30
	for range 20 {
		if err := writeRuntimeEnvironment(directory, deadPID, "generation-gone", time.Now().UTC(), plan, nil, true); err != nil {
			t.Fatal(err)
		}
		state := hookRuntimeState{
			Version: hookRuntimeStateVersion, Generation: "generation-live", PID: os.Getpid(),
			StartedAt: time.Now().UTC(), ProxyURL: plan.Set["HTTPS_PROXY"],
		}
		done := make(chan error, 1)
		go func() { done <- publishHookRuntime(directory, state, plan, nil) }()
		reconcileRuntimeEnvironment(directory, hookRuntimeHealth{})
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		environment, err := os.ReadFile(runtimeEnvironmentPath(directory))
		if err != nil {
			t.Fatal(err)
		}
		var status runtimeEnvironmentStatus
		if err := readOwnerOnlyJSON(runtimeEnvironmentStatusPath(directory), &status); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(environment), proxyBlockBegin) || !status.ProxyLive || status.Generation != "generation-live" {
			t.Fatalf("a stale reconcile retired the replacement's routing: status=%+v\n%s", status, environment)
		}
	}
}

// The transparent-mode files export the reserved names whenever they export
// PHASE_AI_ENABLED=1: outside the proxy guard in env.sh, and in the always
// applied part of env.json, which the OpenCode plugin merges with the rest.
func TestTransparentEnvironmentFilesCarryReservedNames(t *testing.T) {
	plan := testRuntimeEnvironmentPlan()
	plan.Set[phaseproxy.ReservedEnvironmentKey] = "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY"
	for _, live := range []bool{true, false} {
		shell, err := renderRuntimeEnvironment(os.Getpid(), plan, live)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(shell, "export PHASE_AI_ENABLED=") && !strings.Contains(shell, "\nexport "+phaseproxy.ReservedEnvironmentKey+"=") {
			t.Fatalf("env.sh enables Phase AI without %s:\n%s", phaseproxy.ReservedEnvironmentKey, shell)
		}
		document, err := renderRuntimeEnvironmentJSON(os.Getpid(), plan, live)
		if err != nil {
			t.Fatal(err)
		}
		if _, enabled := document.Proxy["PHASE_AI_ENABLED"]; enabled {
			if _, present := document.Set[phaseproxy.ReservedEnvironmentKey]; !present {
				t.Fatalf("env.json enables Phase AI without %s: %+v", phaseproxy.ReservedEnvironmentKey, document)
			}
		}
	}
}
