package proxy

import (
	"path/filepath"
	"strings"
)

// AgentAdapter best-configures a specific agent to route through the proxy and
// trust its CA, leveraging the agent's OWN sandbox where it helps. Phase remains
// the egress proxy; adapters only strengthen/support the integration per agent.
//
// Adapters are conservative: they add safe routing/CA env (additive, can't break
// the agent) and SURFACE the agent's own sandbox-enforcement option via Note
// rather than forcing it on (which could deny things the agent needs).
type AgentAdapter struct {
	Name string
	Note string

	matches []string          // command basenames this applies to
	env     map[string]string // extra env to set on the launched agent
}

var agentAdapters = []AgentAdapter{
	{
		Name:    "Codex CLI",
		matches: []string{"codex"},
		// Codex is Rust (rustls): NODE_EXTRA_CA_CERTS does NOT apply — it trusts
		// CODEX_CA_CERTIFICATE (set generically) and chains egress via HTTPS_PROXY
		// (allow_upstream_proxy defaults on).
		Note: "trusts CODEX_CA_CERTIFICATE, chains via HTTPS_PROXY; enable [features.network_proxy] for its own sandbox enforcement.",
	},
	{
		Name:    "Cursor CLI",
		matches: []string{"cursor-agent", "cursor"},
		env:     map[string]string{"NODE_USE_ENV_PROXY": "1"}, // make its Node honor HTTP(S)_PROXY
		Note:    "NODE_USE_ENV_PROXY=1 + NODE_EXTRA_CA_CERTS; or lean on Cursor's native sandbox allowlist.",
	},
	{
		Name:    "Gemini CLI",
		matches: []string{"gemini"},
		env:     map[string]string{"NODE_USE_SYSTEM_CA": "1"}, // Node trusts system store + NODE_EXTRA_CA_CERTS
		Note:    "honors HTTPS_PROXY + NODE_EXTRA_CA_CERTS; set GEMINI_SANDBOX + GEMINI_SANDBOX_PROXY_COMMAND for OS-sandbox enforcement.",
	},
	{
		Name:    "Claude Code",
		matches: []string{"claude"},
		Note:    "HTTPS_PROXY + NODE_EXTRA_CA_CERTS cover its tool egress; for OS-sandbox enforcement run 'phase proxy start' on a fixed port and set sandbox.network.httpProxyPort + enableWeakerNetworkIsolation in settings.",
	},
	{
		Name:    "Aider",
		matches: []string{"aider"},
		Note:    "no sandbox of its own; HTTPS_PROXY + SSL_CERT_FILE/REQUESTS_CA_BUNDLE route it (Phase supplies the sandbox via run/install).",
	},
	{
		Name:    "GitHub Copilot CLI",
		matches: []string{"copilot"},
		Note:    "local CLI honors HTTPS_PROXY; cloud agent: set HTTPS_PROXY as an Agents variable behind its firewall allowlist.",
	},
}

// AdapterFor returns the adapter matching the command (by basename), or nil.
func AdapterFor(command string) *AgentAdapter {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	for i := range agentAdapters {
		for _, m := range agentAdapters[i].matches {
			if base == m {
				return &agentAdapters[i]
			}
		}
	}
	return nil
}

// Env returns the extra environment entries this adapter applies.
func (a *AgentAdapter) Env() map[string]string { return a.env }
