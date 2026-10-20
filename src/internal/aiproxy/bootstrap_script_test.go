package aiproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func testBootstrapMaterial(t *testing.T) *bootstrapMaterial {
	t.Helper()
	_, caPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &bootstrapMaterial{
		proxyURL: "https://phase:relay-capability@relay.example.test:9543",
		caPEM:    caPEM,
		caPaths:  phaseproxy.CAPaths{Certificate: "/relay/.phase/ai/ca.pem", Bundle: "/relay/.phase/ai/ca-bundle.pem", JavaTrustStore: "/relay/.phase/ai/java-truststore.p12"},
		plan: phaseproxy.ProcessEnvironmentPlan{
			Set: map[string]string{
				"PHASE_AI_ENABLED":      "1",
				"PHASE_AI_CA_BUNDLE":    "/relay/.phase/ai/ca-bundle.pem",
				"HTTPS_PROXY":           "https://phase:relay-capability@relay.example.test:9543",
				"HTTP_PROXY":            "https://phase:relay-capability@relay.example.test:9543",
				"NO_PROXY":              "127.0.0.1,localhost,::1",
				"SSL_CERT_FILE":         "/relay/.phase/ai/ca-bundle.pem",
				"AWS_CA_BUNDLE":         "/relay/.phase/ai/ca-bundle.pem",
				"NODE_EXTRA_CA_CERTS":   "/relay/.phase/ai/ca-bundle.pem",
				"JAVA_TOOL_OPTIONS":     "-Djavax.net.ssl.trustStore=/relay/.phase/ai/java-truststore.p12",
				"AWS_ACCESS_KEY_ID":     "AKIADECOY",
				"AWS_SECRET_ACCESS_KEY": "decoy'with'quotes",
				"PGHOST":                "relay.example.test",
				"PGPORT":                "9544",
				"PGPASSWORD":            "pg-decoy",
				"PGSSLMODE":             "verify-full",
				"PGSSLROOTCERT":         "/relay/.phase/ai/ca-bundle.pem",
			},
			Unset: []string{"PHASE_SERVICE_TOKEN", "AWS_PROFILE"},
		},
		skills:      []BootstrapSkill{{Path: ".claude/skills/phase-cli/SKILL.md", Content: "# phase-cli test skill\n"}, {Path: ".agents/skills/phase-cli/SKILL.md", Content: "# standard skill"}},
		connections: []EndpointConnection{{ConnectionID: "aws-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}, {ConnectionID: "pg-1", ServiceType: "postgres", Protocol: "postgres"}},
	}
}

func TestRenderBootstrapScriptRewritesRelayPathsAndInstallsSkills(t *testing.T) {
	material := testBootstrapMaterial(t)
	script, err := renderBootstrapScript(material)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		strings.TrimSpace(string(material.caPEM)),
		`export HTTPS_PROXY='https://phase:relay-capability@relay.example.test:9543'`,
		`export PHASE_AI_CA_BUNDLE="$HOME/.phase/ai/ca-bundle.pem"`,
		`export AWS_CA_BUNDLE="$HOME/.phase/ai/ca-bundle.pem"`,
		`export PGSSLROOTCERT="$HOME/.phase/ai/ca-bundle.pem"`,
		`export AWS_SECRET_ACCESS_KEY='decoy'"'"'with'"'"'quotes'`,
		`export PGPASSWORD='pg-decoy'`,
		"unset AWS_PROFILE PHASE_SERVICE_TOKEN",
		`cat > "$HOME/.claude/skills/phase-cli/SKILL.md" <<'PHASE_AI_SKILL_EOF'`,
		"# phase-cli test skill",
		`cat > "$HOME/.agents/skills/phase-cli/SKILL.md" <<'PHASE_AI_SKILL_EOF'`,
		"# phase-ai-env-loader v1",
		"aws-prod (aws), pg-1 (postgres)",
		"umask 077",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("bootstrap script missing %q:\n%s", required, script)
		}
	}
	if strings.Contains(script, "/relay/") {
		t.Fatalf("relay-local paths leaked into the sandbox script:\n%s", script)
	}
	if strings.Contains(script, "export JAVA_TOOL_OPTIONS") || strings.Contains(script, "java-truststore") {
		t.Fatalf("Java trust store settings must not be exported into the sandbox:\n%s", script)
	}
	// Replacement roots are appended only when the sandbox has system roots.
	conditional := script[strings.Index(script, `if [ -n "$phase_ai_system_bundle" ]; then`+"\n    cat >>"):]
	if !strings.Contains(conditional, `export SSL_CERT_FILE="$HOME/.phase/ai/ca-bundle.pem"`) {
		t.Fatalf("replacement roots must be conditional:\n%s", script)
	}
	if before := script[:strings.Index(script, "phase_ai_system_bundle=''")]; strings.Contains(before, "SSL_CERT_FILE") {
		t.Fatalf("SSL_CERT_FILE exported unconditionally:\n%s", script)
	}
	if strings.Contains(script, "set -e") || strings.Contains(script, "set -u") {
		t.Fatal("bootstrap must not change the calling shell's options")
	}
}

func TestRenderBootstrapScriptRejectsUnsafeMaterial(t *testing.T) {
	if _, err := renderBootstrapScript(nil); err == nil {
		t.Fatal("nil material was accepted")
	}
	noCA := testBootstrapMaterial(t)
	noCA.caPEM = nil
	if _, err := renderBootstrapScript(noCA); err == nil {
		t.Fatal("missing CA was accepted")
	}
	badSkill := testBootstrapMaterial(t)
	badSkill.skills = []BootstrapSkill{{Path: "../escape/SKILL.md", Content: "x"}}
	if _, err := renderBootstrapScript(badSkill); err == nil {
		t.Fatal("skill path escaping the home directory was accepted")
	}
	badSkill.skills = []BootstrapSkill{{Path: ".claude/skills/$HOME/SKILL.md", Content: "x"}}
	if _, err := renderBootstrapScript(badSkill); err == nil {
		t.Fatal("skill path with shell expansion was accepted")
	}
	badValue := testBootstrapMaterial(t)
	badValue.plan.Set["AWS_REGION"] = "eu-central-1\nexport INJECTED=1"
	if _, err := renderBootstrapScript(badValue); err == nil {
		t.Fatal("newline in an environment value was accepted")
	}
	badKey := testBootstrapMaterial(t)
	badKey.plan.Set["BAD-KEY"] = "x"
	if _, err := renderBootstrapScript(badKey); err == nil {
		t.Fatal("invalid environment key was accepted")
	}
}

func TestBootstrapScriptEvaluatesInRealShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap is a POSIX sh snippet")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}
	script, err := renderBootstrapScript(testBootstrapMaterial(t))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	scriptPath := filepath.Join(home, "bootstrap.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# existing rc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := `eval "$(cat "$1")" || exit 7
printf 'KEY=%s\nPROXY=%s\nBUNDLE=%s\nPROFILE=%s\nSSL=%s\n' "$AWS_ACCESS_KEY_ID" "$HTTPS_PROXY" "$PHASE_AI_CA_BUNDLE" "${AWS_PROFILE:-unset}" "${SSL_CERT_FILE:-unset}"
umask`
	run := func() string {
		command := exec.Command(shell, "-c", probe, "sh", scriptPath)
		command.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "AWS_PROFILE=ambient"}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("bootstrap evaluation failed: %v\n%s", err, output)
		}
		return string(output)
	}
	output := run()
	for _, required := range []string{
		"KEY=AKIADECOY\n", "PROXY=https://phase:relay-capability@relay.example.test:9543\n",
		"BUNDLE=" + filepath.Join(home, ".phase", "ai", "ca-bundle.pem") + "\n", "PROFILE=unset\n",
		"Phase AI relay environment loaded for aws-prod (aws), pg-1 (postgres)",
	} {
		if !strings.Contains(output, required) {
			t.Fatalf("evaluated bootstrap output missing %q:\n%s", required, output)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(output), "0022") && !strings.HasSuffix(strings.TrimSpace(output), "022") {
		t.Fatalf("bootstrap changed the caller's umask:\n%s", output)
	}
	systemBundle := false
	for _, candidate := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/ca-certificates/cert.pem"} {
		if _, err := os.Stat(candidate); err == nil {
			systemBundle = true
			break
		}
	}
	if systemBundle != strings.Contains(output, "SSL="+filepath.Join(home, ".phase", "ai", "ca-bundle.pem")+"\n") {
		t.Fatalf("replacement roots must follow system bundle availability (%v):\n%s", systemBundle, output)
	}
	for _, path := range []string{
		filepath.Join(home, ".phase", "ai", "phase-ca.pem"), filepath.Join(home, ".phase", "ai", "ca-bundle.pem"),
		filepath.Join(home, ".phase", "ai", "env.sh"), filepath.Join(home, ".claude", "skills", "phase-cli", "SKILL.md"),
		filepath.Join(home, ".agents", "skills", "phase-cli", "SKILL.md"), filepath.Join(home, ".profile"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("bootstrap did not create %s: %v", path, err)
		}
		if info.Mode().Perm()&0o077 != 0 && !strings.HasSuffix(path, ".profile") {
			t.Fatalf("%s is not owner-only: %o", path, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".zshrc")); !os.IsNotExist(err) {
		t.Fatal("bootstrap must not create rc files that did not exist")
	}
	run()
	for _, rc := range []string{".profile", ".bashrc"} {
		payload, err := os.ReadFile(filepath.Join(home, rc))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(payload), bootstrapLoaderMark) != 1 || !strings.Contains(string(payload), `. "$HOME/.phase/ai/env.sh"`) {
			t.Fatalf("%s loader is missing or duplicated after two runs:\n%s", rc, payload)
		}
	}
	environment, err := os.ReadFile(filepath.Join(home, ".phase", "ai", "env.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(environment), "\n:\n") || !strings.Contains(string(environment), "export PGPASSWORD='pg-decoy'") {
		t.Fatalf("unexpected env.sh:\n%s", environment)
	}
}

func TestBootstrapRouteIsRemoteOnlyAndRedacted(t *testing.T) {
	client := postgresSession(t, "backend-credential", "decoy-two")
	state, err := newRuntimeStateWithCapability(client, "runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	handler := &controlHandler{state: state}
	request := httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/bootstrap", nil)
	recorder := httptest.NewRecorder()
	handler.serveRoutes(recorder, request, false)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("local proxy served the relay bootstrap: %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.serveRoutes(recorder, request, true)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("relay without bootstrap material answered %d", recorder.Code)
	}
	material := testBootstrapMaterial(t)
	material.plan.Set["PGPASSWORD"] = "decoy-two"
	handler.relayBootstrap = material
	recorder = httptest.NewRecorder()
	handler.serveRoutes(recorder, request, true)
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/x-shellscript") {
		t.Fatalf("bootstrap status=%d type=%q body=%s", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "export PGPASSWORD='decoy-two'") {
		t.Fatal("bootstrap must carry the Agent-visible decoy")
	}
	leaking := testBootstrapMaterial(t)
	leaking.plan.Set["PGPASSWORD"] = "live-db-password"
	handler.relayBootstrap = leaking
	recorder = httptest.NewRecorder()
	handler.serveRoutes(recorder, request, true)
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "live-db-password") {
		t.Fatalf("live material was served: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
