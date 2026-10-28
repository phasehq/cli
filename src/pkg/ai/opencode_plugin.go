package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	OpenCodePluginName      = "phase-ai-bootstrap"
	openCodeOwnershipMarker = "// phase-cli-owned-opencode-plugin; adapter-protocol:" + HarnessAdapterProtocolVersion
)

type OpenCodePluginInstall struct {
	PluginPath      string
	ExecutablePath  string
	EnvironmentPath string
	AdapterProtocol string
}

// DefaultOpenCodePluginPath returns OpenCode's global local-plugin path.
func DefaultOpenCodePluginPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Abs(filepath.Join(openCodeConfigDirectory(home), "plugins", OpenCodePluginName+".js"))
}

// openCodeConfigDirectory is the one global config root OpenCode loads:
// OPENCODE_CONFIG_DIR, else $XDG_CONFIG_HOME/opencode, else ~/.config/opencode
// on every platform, Windows included (not %APPDATA%).
func openCodeConfigDirectory(home string) string {
	if directory := os.Getenv("OPENCODE_CONFIG_DIR"); directory != "" {
		return directory
	}
	if directory := os.Getenv("XDG_CONFIG_HOME"); directory != "" {
		return filepath.Join(directory, "opencode")
	}
	return filepath.Join(home, ".config", "opencode")
}

// InstallOpenCodePlugin installs a dependency-free, provider-agnostic plugin.
// It gives every shell OpenCode spawns the Phase AI environment published by
// the hook-owned proxy daemon (environmentPath, a JSON twin of the file Claude
// Code sources), kicks that daemon, and rewrites explicit phase.invalid
// control calls so they fail with a clear message when the proxy is down.
// Provider discovery stays dynamic; nothing provider-specific is embedded.
func InstallOpenCodePlugin(pluginPath, hookExecutable, environmentPath string) (OpenCodePluginInstall, error) {
	installation := OpenCodePluginInstall{
		PluginPath: pluginPath, ExecutablePath: hookExecutable, EnvironmentPath: environmentPath,
		AdapterProtocol: HarnessAdapterProtocolVersion,
	}
	if pluginPath == "" {
		return installation, errors.New("OpenCode plugin path is required")
	}
	if !filepath.IsAbs(hookExecutable) {
		return installation, errors.New("Phase executable path for OpenCode must be absolute")
	}
	if !filepath.IsAbs(environmentPath) {
		return installation, errors.New("Phase environment path for OpenCode must be absolute")
	}
	if payload, readErr := os.ReadFile(pluginPath); readErr == nil {
		if !isOwnedOpenCodePlugin(string(payload)) {
			return installation, errors.New("refusing to replace an OpenCode plugin not owned by Phase")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return installation, fmt.Errorf("inspect existing OpenCode plugin: %w", readErr)
	}
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		return installation, fmt.Errorf("create OpenCode Phase directory: %w", err)
	}

	helperJSON, err := json.Marshal(hookExecutable)
	if err != nil {
		return installation, err
	}
	environmentJSON, err := json.Marshal(environmentPath)
	if err != nil {
		return installation, err
	}
	source := openCodeOwnershipMarker + `
import { readFileSync } from "node:fs"
import { execFile, execFileSync } from "node:child_process"

const phase = ` + string(helperJSON) + `
const phaseEnvironmentFile = ` + string(environmentJSON) + `
const phaseControlTarget = /(?:^|[\s'"\x60])(?:https?:\/\/)?phase\.invalid(?=[:\/\s'"\x60]|$)/i
const phaseManagedRuntime = /(?:^|[;&|()\s])(?:[^\s;&|()]*\/)?phase(?:-[^\s;&|()]*)?(?:\.exe)?\s+ai\s+exec(?:\s|$)/i
// The daemon is kicked synchronously once per OpenCode process (bounded wait),
// then asynchronously at most this often to keep its session lease fresh.
const phaseKickInterval = 60000
let phaseLastKick = 0

function phaseCommand(command, sessionID) {
  const stdout = execFileSync(
    phase,
    [
      "ai", "__opencode-command",
      "--session", String(sessionID || ""),
      "--command", Buffer.from(command, "utf8").toString("base64url"),
    ],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 45000, maxBuffer: 4 * 1024 * 1024 },
  )
  const response = JSON.parse(stdout)
  if (response.schemaVersion !== 1 || typeof response.managed !== "boolean") {
    throw new Error("Phase AI returned an invalid OpenCode command response")
  }
  return response
}

// Returns the replacement command, null to leave the command untouched, or
// throws when an explicit Phase control call cannot reach the proxy.
function rewritePhaseCommand(command, sessionID) {
  if (typeof command !== "string" || command.trim() === "") return null
  if (!phaseControlTarget.test(command) || phaseManagedRuntime.test(command)) return null
  let response
  try {
    response = phaseCommand(command, sessionID)
  } catch {
    // Keep the original command untouched. A real phase.invalid control call
    // will fail naturally; an incidental mention must never block ambient work.
    return null
  }
  if (!response.managed) return null
  if (typeof response.command === "string" && response.command.trim() !== "") return response.command
  throw new Error(response.error || "This explicit Phase command needs the authenticated proxy, but it is unavailable. Unrelated tools remain available.")
}

function phaseProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return Boolean(error) && error.code === "EPERM"
  }
}

// Reads the daemon-published environment. Decoys and adapter endpoints apply
// whenever the file exists; proxy routing and trust overrides apply only while
// the proxy process that wrote them is alive, so a crashed proxy never strands
// a shell behind a dead port.
function phaseEnvironment() {
  let payload
  try {
    payload = JSON.parse(readFileSync(phaseEnvironmentFile, "utf8"))
  } catch {
    return null
  }
  if (!payload || payload.schema !== 1 || !payload.set || typeof payload.set !== "object") return null
  const live = payload.proxyLive === true && phaseProcessAlive(payload.pid)
  return {
    set: payload.set,
    proxy: live && payload.proxy && typeof payload.proxy === "object" ? payload.proxy : {},
    unset: Array.isArray(payload.unset) ? payload.unset : [],
  }
}

// Starts or repairs the Phase proxy daemon and renews this process's session
// lease. Never throws and never blocks longer than the bounded first wait.
function phaseKick() {
  const now = Date.now()
  const first = phaseLastKick === 0
  if (!first && now - phaseLastKick < phaseKickInterval) return
  phaseLastKick = now
  const args = ["ai", "__opencode-session", "--session", "pid-" + String(process.pid)]
  const options = { stdio: "ignore", windowsHide: true }
  try {
    if (first) {
      execFileSync(phase, args, { ...options, timeout: 2000 })
      return
    }
    const child = execFile(phase, args, { ...options, timeout: 5000 }, () => {})
    if (child && typeof child.unref === "function") child.unref()
  } catch {
    // The next shell command retries; ordinary work is never blocked.
  }
}

// Applies the Phase AI environment to one shell's environment object. An
// environment inherited from a Phase-managed launcher already carries everything.
function phaseApplyEnvironment(env) {
  if (!env || typeof env !== "object") return
  if (env.PHASE_AI_ENABLED === "1") return
  phaseKick()
  const phaseEnv = phaseEnvironment()
  if (!phaseEnv) return
  for (const key of phaseEnv.unset) delete env[key]
  Object.assign(env, phaseEnv.set, phaseEnv.proxy)
}

// OpenCode 1.x reads server() from the default export and expects a hooks object.
async function phaseServer() {
  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = output?.args?.command
      const replacement = rewritePhaseCommand(command, input.sessionID)
      if (replacement !== null) output.args.command = replacement
    },
    "shell.env": async (_input, output) => {
      phaseApplyEnvironment(output?.env)
    },
  }
}

// OpenCode 2.x reads setup(context) from the default export; hooks are
// registered through the context and the tool input is edited in place. Its
// command tool is named shell rather than 1.x's bash.
async function phaseSetup(context) {
  await context.tool.hook("execute.before", async (event) => {
    if (event.tool !== "shell") return
    const args = event.input
    const command = args && typeof args === "object" ? args.command : undefined
    const replacement = rewritePhaseCommand(command, event.sessionID)
    if (replacement === null) return
    args.command = replacement
    event.input = args
  })
  if (context.shell && typeof context.shell.hook === "function") {
    await context.shell.hook("create.before", async (shell) => {
      phaseApplyEnvironment(shell?.env)
    })
  }
}

// One default export satisfies both loaders: 1.x uses server(), 2.x uses
// setup() and ignores the extra key. A named plugin export must not exist,
// or 1.x would register the hooks twice.
const phaseAIPlugin = { id: "phase-ai-bootstrap", server: phaseServer, setup: phaseSetup }
export default phaseAIPlugin
`
	if err := writePrivateTextFile(pluginPath, source); err != nil {
		return installation, fmt.Errorf("write OpenCode Phase plugin: %w", err)
	}
	return installation, nil
}

func isOwnedOpenCodePlugin(source string) bool {
	return strings.HasPrefix(source, openCodeOwnershipMarker+"\n")
}

// UninstallOpenCodePlugin removes only files with a Phase ownership marker.
func UninstallOpenCodePlugin(pluginPath string) error {
	base := filepath.Base(filepath.Clean(pluginPath))
	if pluginPath == "" || base != OpenCodePluginName+".js" {
		return errors.New("refusing to remove an unexpected OpenCode plugin path")
	}
	_, err := removeOwnedOpenCodePluginFile(pluginPath, true)
	return err
}

func removeOwnedOpenCodePluginFile(path string, requireOwnership bool) (bool, error) {
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read OpenCode Phase plugin: %w", err)
	}
	if !isOwnedOpenCodePlugin(string(payload)) {
		if requireOwnership {
			return false, errors.New("refusing to remove an OpenCode plugin not owned by Phase")
		}
		return false, nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove OpenCode Phase plugin: %w", err)
	}
	return true, nil
}
