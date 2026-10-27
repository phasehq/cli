package ai

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestInstallOpenCodePluginIsDependencyFreeAndIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, ".config", "opencode", "plugins", OpenCodePluginName+".js")
	first := filepath.Join(home, "first-phase")
	if err := os.WriteFile(first, []byte("first"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := InstallSharedHookExecutable(first)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := InstallOpenCodePlugin(pluginPath, shared.ExecutablePath, filepath.Join(home, ".phase", "ai", "env.json"))
	if err != nil {
		t.Fatal(err)
	}
	if installation.AdapterProtocol != HarnessAdapterProtocolVersion || installation.ExecutablePath != shared.ExecutablePath {
		t.Fatalf("unexpected OpenCode installation: %#v", installation)
	}
	payload, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, required := range []string{
		openCodeOwnershipMarker, `"tool.execute.before"`, `input.tool !== "bash"`,
		`if (!phaseControlTarget.test(command) || phaseManagedRuntime.test(command)) return null`,
		`catch {`, `incidental mention must never block ambient work`,
		`output.args.command = replacement`, `phase\.invalid`, `phaseManagedRuntime`,
		`__opencode-command`, "execFileSync",
		// OpenCode 2.x requires a default export with id and setup(); 1.x reads server().
		`export default phaseAIPlugin`, `id: "phase-ai-bootstrap"`, `server: phaseServer`, `setup: phaseSetup`,
		`context.tool.hook("execute.before"`, `event.tool !== "bash"`,
		// Transparent mode: the daemon-published environment is applied to every
		// shell, routing only while the proxy PID is alive; the daemon is kicked.
		`"shell.env"`, `context.shell.hook("create.before"`, `__opencode-session`, `phaseEnvironmentFile`,
		`process.kill(pid, 0)`, `env.PHASE_AI_ENABLED === "1"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("OpenCode plugin missing %q: %s", required, source)
		}
	}
	for _, forbidden := range []string{
		"export const PhaseAIPlugin", "export const ", "export async function ",
		"phase ai run", `process.env.PHASE_AI_ENABLED`,
		`directManagedCommands`, `isDirectManagedCommand`, `commandWrappers`, `managedNetworkTarget`,
		`amazonaws.com`, `aws sts`, `psql`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("OpenCode plugin still contains global environment behavior or workaround guidance %q", forbidden)
		}
	}
	for _, forbidden := range []string{"PHASE_SERVICE_TOKEN", "AWS_SECRET_ACCESS_KEY", "HTTPS_PROXY="} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("OpenCode plugin contains runtime material %q", forbidden)
		}
	}
	if data, err := os.ReadFile(shared.ExecutablePath); err != nil || string(data) != "first" {
		t.Fatalf("unexpected installed helper: %q, %v", data, err)
	}

	second := filepath.Join(home, "second-phase")
	if err := os.WriteFile(second, []byte("second"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSharedHookExecutable(second); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallOpenCodePlugin(pluginPath, shared.ExecutablePath, filepath.Join(home, ".phase", "ai", "env.json")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(shared.ExecutablePath); err != nil || string(data) != "second" {
		t.Fatalf("OpenCode helper was not refreshed: %q, %v", data, err)
	}
}

func TestInstalledOpenCodeOnlyDelegatesExplicitPhaseControlCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, OpenCodePluginName+".js")
	helper := filepath.Join(home, "phase-hook-v1")
	helperSource := "#!/bin/sh\nprintf '%s\\n' '{\"schemaVersion\":1,\"managed\":true,\"command\":\"phase-rewritten\"}'\n"
	if err := os.WriteFile(helper, []byte(helperSource), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallOpenCodePlugin(pluginPath, helper, filepath.Join(home, ".phase", "ai", "env.json")); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		Command string `json:"command"`
		Want    string `json:"want"`
	}{
		{Command: "git status && gh pr create --fill", Want: "git status && gh pr create --fill"},
		{Command: "aws sts get-caller-identity", Want: "aws sts get-caller-identity"},
		{Command: "psql postgres://localhost/test", Want: "psql postgres://localhost/test"},
		{Command: "curl https://sts.amazonaws.com", Want: "curl https://sts.amazonaws.com"},
		{Command: "phase ai exec -- curl http://phase.invalid/v1/status", Want: "phase ai exec -- curl http://phase.invalid/v1/status"},
		{Command: "/tmp/phase-dev ai exec -- curl http://phase.invalid/v1/status", Want: "/tmp/phase-dev ai exec -- curl http://phase.invalid/v1/status"},
		{Command: `C:/Phase/phase.exe ai exec -- curl http://phase.invalid/v1/status`, Want: `C:/Phase/phase.exe ai exec -- curl http://phase.invalid/v1/status`},
		{Command: "curl http://phase.invalid/v1/status", Want: "phase-rewritten"},
	}
	casesJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	module := append([]byte(nil), source...)
	module = append(module, []byte("\nconst commandCases = "+string(casesJSON)+`;
// OpenCode 1.x contract: default.server() returns a hooks object.
const plugin = await phaseAIPlugin.server();
for (const item of commandCases) { const output = { args: { command: item.command } }; await plugin["tool.execute.before"]({ tool: "bash", sessionID: "test" }, output); const got = output.args.command; if (got !== item.want) throw new Error(JSON.stringify({ ...item, got, api: "server" })); }
// OpenCode 2.x contract: default.setup(context) registers tool.hook("execute.before").
const registered = {};
await phaseAIPlugin.setup({ tool: { hook: async (name, callback) => { registered[name] = callback; return { dispose: async () => {} }; } } });
if (typeof registered["execute.before"] !== "function") throw new Error("setup did not register execute.before");
for (const item of commandCases) { const event = { tool: "bash", sessionID: "test", input: { command: item.command } }; await registered["execute.before"](event); if (event.input.command !== item.want) throw new Error(JSON.stringify({ ...item, got: event.input.command, api: "setup" })); }
const other = { tool: "read", sessionID: "test", input: { filePath: "http://phase.invalid/x" } };
await registered["execute.before"](other);
if (other.input.filePath !== "http://phase.invalid/x") throw new Error("non-bash tool input was modified");
`)...)
	modulePath := filepath.Join(home, "phase-ai-classifier.mjs")
	if err := os.WriteFile(modulePath, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, modulePath).CombinedOutput(); err != nil {
		t.Fatalf("generated OpenCode delegation boundary failed: %v\n%s", err, output)
	}
	if err := os.Remove(helper); err != nil {
		t.Fatal(err)
	}
	fallbackModule := append([]byte(nil), source...)
	fallbackModule = append(fallbackModule, []byte(`
const fallbackPlugin = await phaseAIPlugin.server()
for (const command of ["aws sts get-caller-identity", "git commit -m 'mention phase.invalid'", "curl http://phase.invalid/v1/status"]) {
  const output = { args: { command } }
  await fallbackPlugin["tool.execute.before"]({ tool: "bash", sessionID: "test" }, output)
  if (output.args.command !== command) throw new Error(JSON.stringify({ command, got: output.args.command }))
}
`)...)
	fallbackPath := filepath.Join(home, "phase-ai-helper-unavailable.mjs")
	if err := os.WriteFile(fallbackPath, fallbackModule, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, fallbackPath).CombinedOutput(); err != nil {
		t.Fatalf("unavailable OpenCode helper blocked ambient work: %v\n%s", err, output)
	}
}

func TestInstalledOpenCodePluginAppliesPublishedEnvironmentOnlyWhileProxyIsAlive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, OpenCodePluginName+".js")
	helper := filepath.Join(home, "phase-hook-v1")
	kickLog := filepath.Join(home, "kicks.log")
	helperSource := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + strconv.Quote(kickLog) + "\n"
	if err := os.WriteFile(helper, []byte(helperSource), 0o700); err != nil {
		t.Fatal(err)
	}
	environmentPath := filepath.Join(home, ".phase", "ai", "env.json")
	if err := os.MkdirAll(filepath.Dir(environmentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallOpenCodePlugin(pluginPath, helper, environmentPath); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	module := append([]byte(nil), source...)
	module = append(module, []byte(`
import { writeFileSync, unlinkSync } from "node:fs"
const environmentFile = `+strconv.Quote(environmentPath)+`
const live = { schema: 1, pid: process.pid, proxyLive: true, set: { AWS_ACCESS_KEY_ID: "AKIADECOY", PGPASSWORD: "pg-decoy" }, proxy: { HTTPS_PROXY: "http://phase:capability@127.0.0.1:9543", PHASE_AI_ENABLED: "1" }, unset: ["AWS_PROFILE"] }
function check(condition, message) { if (!condition) throw new Error(message) }
writeFileSync(environmentFile, JSON.stringify(live))
// OpenCode 1.x contract: default.server()["shell.env"] mutates output.env.
const plugin = await phaseAIPlugin.server()
const output = { env: { AWS_PROFILE: "ambient", KEEP: "1" } }
await plugin["shell.env"]({ cwd: "/tmp" }, output)
check(output.env.AWS_ACCESS_KEY_ID === "AKIADECOY" && output.env.HTTPS_PROXY === "http://phase:capability@127.0.0.1:9543" && output.env.PHASE_AI_ENABLED === "1", "live environment was not applied: " + JSON.stringify(output.env))
check(!("AWS_PROFILE" in output.env) && output.env.KEEP === "1", "unset or unrelated keys mishandled: " + JSON.stringify(output.env))
// OpenCode 2.x contract: setup(context) registers shell.hook("create.before").
const hooks = {}
await phaseAIPlugin.setup({
  tool: { hook: async (name, callback) => { hooks["tool:" + name] = callback } },
  shell: { hook: async (name, callback) => { hooks["shell:" + name] = callback } },
})
check(typeof hooks["shell:create.before"] === "function", "setup did not register shell create.before")
const shell = { command: "aws sts get-caller-identity", cwd: "/tmp", env: { AWS_PROFILE: "ambient" } }
await hooks["shell:create.before"](shell)
check(shell.env.AWS_ACCESS_KEY_ID === "AKIADECOY" && shell.env.HTTPS_PROXY && !("AWS_PROFILE" in shell.env) && shell.command === "aws sts get-caller-identity", "2.x shell environment was not applied: " + JSON.stringify(shell))
// A dead proxy PID keeps decoys and drops routing.
writeFileSync(environmentFile, JSON.stringify({ ...live, pid: 999999999 }))
const degraded = { env: {} }
await plugin["shell.env"]({}, degraded)
check(degraded.env.AWS_ACCESS_KEY_ID === "AKIADECOY" && degraded.env.PGPASSWORD === "pg-decoy" && degraded.env.HTTPS_PROXY === undefined && degraded.env.PHASE_AI_ENABLED === undefined, "dead proxy routing leaked: " + JSON.stringify(degraded.env))
// An environment inherited from phase ai run is left alone.
writeFileSync(environmentFile, JSON.stringify(live))
const inherited = { env: { PHASE_AI_ENABLED: "1", HTTPS_PROXY: "http://inherited" } }
await plugin["shell.env"]({}, inherited)
check(inherited.env.HTTPS_PROXY === "http://inherited" && inherited.env.AWS_ACCESS_KEY_ID === undefined, "inherited environment was modified")
// No published environment means ambient credentials, untouched.
unlinkSync(environmentFile)
const missing = { env: { ONLY: "1" } }
await plugin["shell.env"]({}, missing)
check(Object.keys(missing.env).length === 1 && missing.env.ONLY === "1", "missing environment modified the shell")
`)...)
	modulePath := filepath.Join(home, "phase-ai-environment.mjs")
	if err := os.WriteFile(modulePath, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, modulePath).CombinedOutput(); err != nil {
		t.Fatalf("OpenCode environment injection failed: %v\n%s", err, output)
	}
	kicks, err := os.ReadFile(kickLog)
	if err != nil {
		t.Fatalf("plugin never kicked the Phase daemon: %v", err)
	}
	if !strings.Contains(string(kicks), "ai __opencode-session --session pid-") {
		t.Fatalf("unexpected daemon kick: %s", kicks)
	}
	if strings.Count(string(kicks), "__opencode-session") != 1 {
		t.Fatalf("daemon kick was not throttled: %s", kicks)
	}
}

func TestUninstallOpenCodePluginPreservesForeignFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, ".config", "opencode", "plugins", OpenCodePluginName+".js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginPath, []byte("export const Foreign = async () => ({})\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UninstallOpenCodePlugin(pluginPath); err == nil {
		t.Fatal("foreign OpenCode plugin was accepted for removal")
	}
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("foreign OpenCode plugin was removed: %v", err)
	}
}

func TestUninstallOpenCodePluginRemovesOwnedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, ".config", "opencode", "plugins", OpenCodePluginName+".js")
	executable := filepath.Join(home, "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	installation, err := InstallOpenCodePlugin(pluginPath, executable, filepath.Join(home, ".phase", "ai", "env.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := UninstallOpenCodePlugin(pluginPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("owned plugin remains after uninstall: %v", err)
	}
	if _, err := os.Stat(installation.ExecutablePath); err != nil {
		t.Fatalf("shared helper was removed with one adapter: %v", err)
	}
}

func TestInstalledOpenCodePluginExportsOneDefaultDefinition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test imports the plugin with a POSIX node invocation")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pluginPath := filepath.Join(home, ".config", "opencode", "plugins", OpenCodePluginName+".js")
	if _, err := InstallOpenCodePlugin(pluginPath, filepath.Join(home, "phase-hook-v1"), filepath.Join(home, ".phase", "ai", "env.json")); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(home, "probe.mjs")
	script := "import { pathToFileURL } from 'node:url';\n" +
		"const mod = await import(pathToFileURL(" + strconv.Quote(pluginPath) + ").href);\n" +
		"const keys = Object.keys(mod).sort();\n" +
		"if (keys.length !== 1 || keys[0] !== 'default') throw new Error('exports: ' + keys.join(','));\n" +
		"if (mod.default.id !== 'phase-ai-bootstrap' || typeof mod.default.setup !== 'function' || typeof mod.default.server !== 'function') throw new Error('bad default definition: ' + JSON.stringify(Object.keys(mod.default)));\n"
	if err := os.WriteFile(probe, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, probe).CombinedOutput(); err != nil {
		t.Fatalf("OpenCode plugin module shape: %v\n%s", err, output)
	}
}

func TestDefaultOpenCodePluginPathUsesDotConfigOnEveryPlatform(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := DefaultOpenCodePluginPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "opencode", "plugins", OpenCodePluginName+".js"); path != want {
		t.Fatalf("plugin path = %s, want %s", path, want)
	}
}
