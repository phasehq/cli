package aiproxy

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// bootstrapMaterial is everything the relay needs to render the one-shot
// sandbox bootstrap served at GET http://phase.invalid/v1/bootstrap. It is
// assembled once per backend session; the proxy URL and decoys inside it are
// exactly what the authenticated client already holds.
type bootstrapMaterial struct {
	proxyURL    string
	caPEM       []byte
	caPaths     phaseproxy.CAPaths
	plan        phaseproxy.ProcessEnvironmentPlan
	skills      []BootstrapSkill
	connections []EndpointConnection
}

const (
	bootstrapSchema          = 1
	bootstrapHomeRelative    = ".phase/ai"
	bootstrapCAFile          = "phase-ca.pem"
	bootstrapBundleFile      = "ca-bundle.pem"
	bootstrapEnvironmentFile = "env.sh"
	bootstrapLoaderMark      = "# phase-ai-env-loader v1"
	bootstrapCATerminator    = "PHASE_AI_CA_EOF"
	bootstrapEnvTerminator   = "PHASE_AI_ENV_EOF"
	bootstrapSkillTerm       = "PHASE_AI_SKILL_EOF"
)

// replacementRootKeys point global TLS clients at a bundle that replaces the
// system store. The sandbox decides at bootstrap time whether it could merge
// its own system roots into that bundle; without them these must stay unset.
var replacementRootKeys = []string{
	"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
	"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "NIX_SSL_CERT_FILE", "PIP_CERT", "DENO_CERT",
}

func isReplacementRootKey(key string) bool {
	for _, candidate := range replacementRootKeys {
		if candidate == key {
			return true
		}
	}
	return false
}

// renderBootstrapScript produces a POSIX sh snippet meant to be evaluated in
// the sandbox's current shell (eval "$(curl ...)"). It writes the Phase CA, a
// merged trust bundle, the Phase AI environment file and the Agent skills,
// loads the environment into the calling shell and arranges for future login
// shells to load it. File writes happen in a subshell so the caller's umask and
// variables are untouched.
func renderBootstrapScript(material *bootstrapMaterial) (string, error) {
	if material == nil || material.proxyURL == "" || len(material.caPEM) == 0 {
		return "", errors.New("relay bootstrap material is incomplete")
	}
	caPEM := strings.TrimSpace(string(material.caPEM))
	if !strings.HasPrefix(caPEM, "-----BEGIN CERTIFICATE-----") || strings.Contains(caPEM, bootstrapCATerminator) {
		return "", errors.New("relay CA certificate is invalid")
	}
	environment, err := renderBootstrapEnvironment(material)
	if err != nil {
		return "", err
	}
	if strings.Contains(environment, bootstrapEnvTerminator) {
		return "", errors.New("relay environment contains a reserved terminator")
	}
	homeDirectory := "$HOME/" + bootstrapHomeRelative
	var out strings.Builder
	fmt.Fprintf(&out, "# Phase AI relay bootstrap (schema %d). Evaluate in the sandbox shell: eval \"$(curl ...)\"\n", bootstrapSchema)
	out.WriteString("phase_ai_home=\"" + homeDirectory + "\"\n")
	out.WriteString("phase_ai_ok=1\n")
	out.WriteString("(\n")
	out.WriteString("  umask 077\n")
	out.WriteString("  mkdir -p \"$phase_ai_home\" || exit 1\n")
	out.WriteString("  cat > \"$phase_ai_home/" + bootstrapCAFile + "\" <<'" + bootstrapCATerminator + "'\n")
	out.WriteString(caPEM + "\n")
	out.WriteString(bootstrapCATerminator + "\n")
	out.WriteString("  phase_ai_system_bundle=''\n")
	out.WriteString("  for phase_ai_candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/pki/tls/cacert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem /usr/local/etc/openssl/cert.pem /opt/homebrew/etc/ca-certificates/cert.pem; do\n")
	out.WriteString("    if [ -r \"$phase_ai_candidate\" ]; then phase_ai_system_bundle=\"$phase_ai_candidate\"; break; fi\n")
	out.WriteString("  done\n")
	out.WriteString("  if [ -n \"$phase_ai_system_bundle\" ]; then\n")
	out.WriteString("    cat \"$phase_ai_system_bundle\" \"$phase_ai_home/" + bootstrapCAFile + "\" > \"$phase_ai_home/" + bootstrapBundleFile + "\" || exit 1\n")
	out.WriteString("  else\n")
	out.WriteString("    cp \"$phase_ai_home/" + bootstrapCAFile + "\" \"$phase_ai_home/" + bootstrapBundleFile + "\" || exit 1\n")
	out.WriteString("  fi\n")
	out.WriteString("  cat > \"$phase_ai_home/" + bootstrapEnvironmentFile + "\" <<'" + bootstrapEnvTerminator + "'\n")
	out.WriteString(environment)
	out.WriteString(bootstrapEnvTerminator + "\n")
	out.WriteString("  if [ -n \"$phase_ai_system_bundle\" ]; then\n")
	out.WriteString("    cat >> \"$phase_ai_home/" + bootstrapEnvironmentFile + "\" <<'" + bootstrapEnvTerminator + "'\n")
	out.WriteString("# Replacement trust roots: this bundle also carries the sandbox's system roots.\n")
	for _, key := range replacementRootKeys {
		out.WriteString("export " + key + "=\"$HOME/" + bootstrapHomeRelative + "/" + bootstrapBundleFile + "\"\n")
	}
	out.WriteString(bootstrapEnvTerminator + "\n")
	out.WriteString("  else\n")
	out.WriteString("    printf '%s\\n' '# No system trust store was found; global replacement roots stay unset.' >> \"$phase_ai_home/" + bootstrapEnvironmentFile + "\"\n")
	out.WriteString("  fi\n")
	out.WriteString("  printf ':\\n' >> \"$phase_ai_home/" + bootstrapEnvironmentFile + "\"\n")
	for _, skill := range material.skills {
		relative, err := bootstrapSkillRelativePath(skill.Path)
		if err != nil {
			return "", err
		}
		if strings.Contains(skill.Content, bootstrapSkillTerm) {
			return "", errors.New("relay skill contains a reserved terminator")
		}
		out.WriteString("  mkdir -p \"$HOME/" + path.Dir(relative) + "\" && cat > \"$HOME/" + relative + "\" <<'" + bootstrapSkillTerm + "'\n")
		out.WriteString(strings.TrimRight(skill.Content, "\n") + "\n")
		out.WriteString(bootstrapSkillTerm + "\n")
	}
	// Future login and interactive shells load the environment too.
	out.WriteString("  for phase_ai_rc in \"$HOME/.profile\" \"$HOME/.bashrc\" \"$HOME/.zshrc\"; do\n")
	out.WriteString("    if [ \"$phase_ai_rc\" != \"$HOME/.profile\" ] && [ ! -f \"$phase_ai_rc\" ]; then continue; fi\n")
	out.WriteString("    if [ -f \"$phase_ai_rc\" ] && grep -q '" + bootstrapLoaderMark + "' \"$phase_ai_rc\" 2>/dev/null; then continue; fi\n")
	out.WriteString("    printf '\\n%s\\nif [ -r \"$HOME/" + bootstrapHomeRelative + "/" + bootstrapEnvironmentFile + "\" ]; then . \"$HOME/" + bootstrapHomeRelative + "/" + bootstrapEnvironmentFile + "\"; fi\\n' '" + bootstrapLoaderMark + "' >> \"$phase_ai_rc\"\n")
	out.WriteString("  done\n")
	out.WriteString(") || phase_ai_ok=0\n")
	out.WriteString("if [ \"$phase_ai_ok\" = 1 ]; then\n")
	out.WriteString("  . \"$phase_ai_home/" + bootstrapEnvironmentFile + "\"\n")
	fmt.Fprintf(&out, "  printf '%%s\\n' %s\n", shellSingleQuote(bootstrapSummary(material)))
	out.WriteString("else\n")
	out.WriteString("  printf '%s\\n' 'Phase AI relay bootstrap failed; nothing was loaded into this shell.' >&2\n")
	out.WriteString("fi\n")
	out.WriteString("unset phase_ai_home phase_ai_ok\n")
	return out.String(), nil
}

// renderBootstrapEnvironment renders the sandbox-side env.sh body. Values
// that name files on the relay are rewritten to the sandbox paths the
// bootstrap creates; everything else is exported verbatim. Unlike the local
// transparent-mode file there is no liveness guard: the relay is remote, so a
// dead relay surfaces as a connection error on Phase-managed traffic only.
func renderBootstrapEnvironment(material *bootstrapMaterial) (string, error) {
	plan := material.plan
	keys := make([]string, 0, len(plan.Set))
	for key := range plan.Set {
		if !phaseproxy.ValidShellEnvironmentKey(key) {
			return "", fmt.Errorf("environment key %q is not a valid shell identifier", key)
		}
		if strings.ContainsAny(plan.Set[key], "\x00\r\n") {
			return "", fmt.Errorf("environment key %s has an unsafe value", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	unsets := append([]string(nil), plan.Unset...)
	sort.Strings(unsets)
	for _, key := range unsets {
		if !phaseproxy.ValidShellEnvironmentKey(key) {
			return "", fmt.Errorf("environment unset %q is not a valid shell identifier", key)
		}
	}
	bundlePath := "\"$HOME/" + bootstrapHomeRelative + "/" + bootstrapBundleFile + "\""
	certificatePath := "\"$HOME/" + bootstrapHomeRelative + "/" + bootstrapCAFile + "\""
	var out strings.Builder
	fmt.Fprintf(&out, "# Phase AI relay environment (schema %d). Written by the relay bootstrap; do not edit.\n", bootstrapSchema)
	out.WriteString("# Re-run the relay handoff line to refresh it. Remove this file and the\n")
	out.WriteString("# loader lines in ~/.profile, ~/.bashrc and ~/.zshrc to return to ambient credentials.\n")
	if len(unsets) > 0 {
		out.WriteString("unset " + strings.Join(unsets, " ") + "\n")
	}
	for _, key := range keys {
		value := plan.Set[key]
		switch {
		case isReplacementRootKey(key):
			// Appended by the bootstrap only when the sandbox has system roots.
			continue
		case key == "JAVA_TOOL_OPTIONS":
			out.WriteString("# JAVA_TOOL_OPTIONS is not set: import " + bootstrapCAFile + " into the JVM trust store to use Java clients.\n")
			continue
		case material.caPaths.Bundle != "" && value == material.caPaths.Bundle:
			out.WriteString("export " + key + "=" + bundlePath + "\n")
		case material.caPaths.Certificate != "" && value == material.caPaths.Certificate:
			out.WriteString("export " + key + "=" + certificatePath + "\n")
		default:
			out.WriteString("export " + key + "=" + shellSingleQuote(value) + "\n")
		}
	}
	return out.String(), nil
}

func bootstrapSkillRelativePath(value string) (string, error) {
	cleaned := path.Clean(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	if cleaned == "" || cleaned == "." || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "../") || cleaned == ".." ||
		strings.ContainsAny(cleaned, "\x00\r\n'\"$`") || !strings.HasSuffix(cleaned, ".md") {
		return "", fmt.Errorf("relay skill path %q is invalid", value)
	}
	return cleaned, nil
}

func bootstrapSummary(material *bootstrapMaterial) string {
	names := make([]string, 0, len(material.connections))
	for _, connection := range material.connections {
		label := strings.TrimSpace(connection.Name)
		if label == "" {
			label = connection.ConnectionID
		}
		names = append(names, label+" ("+connection.ServiceType+")")
	}
	summary := "Phase AI relay environment loaded"
	if len(names) > 0 {
		summary += " for " + strings.Join(names, ", ")
	} else {
		summary += "; this Workflow has no Connections yet"
	}
	return summary + ". New login shells load ~/" + bootstrapHomeRelative + "/" + bootstrapEnvironmentFile + " automatically."
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// bootstrap serves the sandbox bootstrap snippet. The caller already proved it
// holds the proxy capability, which is the only secret the snippet repeats.
func (h *controlHandler) serveBootstrap(w http.ResponseWriter, req *http.Request) {
	if h.relayBootstrap == nil {
		writeControlError(w, http.StatusNotFound, "control_route_not_found", "The remote control route was not found.", false)
		return
	}
	if err := h.state.availability(); err != nil {
		writeControlError(w, http.StatusServiceUnavailable, "agent_session_unavailable", "The Phase AI session is not available.", true)
		return
	}
	script, err := renderBootstrapScript(h.relayBootstrap)
	if err != nil {
		writeControlError(w, http.StatusBadGateway, "relay_bootstrap_unavailable", "The relay bootstrap could not be rendered.", false)
		return
	}
	// The snippet carries decoys and the client's own proxy credential, never
	// live credential material or the backend session credential.
	if manifestPayloadContains([]byte(script), append(h.state.manifestPayloadForbiddenSecrets(), h.state.currentBackendCredential().Reveal())) {
		writeControlError(w, http.StatusBadGateway, "unsafe_relay_bootstrap", "The relay bootstrap contained proxy-only material.", false)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write([]byte(script))
}
