package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A Phase secret named "<PROVIDER>_POLICY" holds a JSON binding doc; it lives in
// a per-provider folder next to the live credential and the dummy placeholder
// (e.g. /github/{GITHUB_TOKEN,GITHUB_DUMMY,GITHUB_POLICY}). The proxy fetches
// the whole app/environment from Phase itself and discovers providers by the
// _POLICY suffix. (PoC stand-in for future dedicated credential/policy APIs.)
const policySuffix = "_POLICY"

func Dir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".phase", "proxy")
}

func CACertPath() string   { return filepath.Join(Dir(), "ca.pem") }
func AgentEnvPath() string { return filepath.Join(Dir(), "agent.env") }

func WriteCACert(certPEM []byte) (string, error) {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return "", err
	}
	p := CACertPath()
	if err := os.WriteFile(p, certPEM, 0644); err != nil {
		return "", err
	}
	return p, nil
}

func ReadCACert() ([]byte, error) { return os.ReadFile(CACertPath()) }

// CABundlePath is the combined trust bundle (system roots + proxy CA).
func CABundlePath() string { return filepath.Join(Dir(), "ca-bundle.pem") }

// systemCAFiles are well-known system CA bundle locations (Linux/BSD/macOS-brew).
var systemCAFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Arch
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora/RHEL
	"/etc/pki/tls/certs/ca-bundle.crt",                  // older Fedora/RHEL
	"/etc/ssl/ca-bundle.pem",                            // openSUSE
	"/etc/ssl/cert.pem",                                 // Alpine, macOS (brew)
}

// EnsureCABundle writes a trust bundle = system roots + the proxy CA, so tools
// that REPLACE their trust store (curl, python requests, git, AWS CLI) still
// validate BOTH real upstream certs (passthrough hosts) and the proxy's MITM
// leaf (intercepted hosts). Returns its path. If no system bundle file is found
// (macOS/Windows keep roots in the OS store), it falls back to just the proxy CA
// — REPLACE-type tools then won't trust passthrough hosts there, but ADD-type
// runtimes (Node's NODE_EXTRA_CA_CERTS) still work.
func EnsureCABundle() (string, error) {
	ours, err := ReadCACert()
	if err != nil {
		return "", err
	}
	var sys []byte
	for _, f := range systemCAFiles {
		if b, e := os.ReadFile(f); e == nil && len(b) > 0 {
			sys = b
			break
		}
	}
	var buf bytes.Buffer
	if len(sys) > 0 {
		buf.Write(sys)
		if sys[len(sys)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	buf.Write(ours)
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return "", err
	}
	p := CABundlePath()
	if err := os.WriteFile(p, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return p, nil
}

// WriteAgentEnv persists the agent provisioning file. It contains only dummy
// placeholders + routing + CA path, so it is non-secret (0644).
func WriteAgentEnv(content string) (string, error) {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return "", err
	}
	p := AgentEnvPath()
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		return "", err
	}
	return p, nil
}

type Config struct {
	Bindings []Binding
}

// Binding is one provider, parsed from a <PROVIDER>_POLICY secret.
type Binding struct {
	Provider       string   `json:"-"`                        // derived from the secret name
	Host           string   `json:"host"`                     // api.github.com, or host:port for DBs
	Protocol       string   `json:"protocol,omitempty"`       // "http" (default) | "postgres" | ...
	ListenPort     int      `json:"listenPort,omitempty"`     // DB explicit mode: local port the agent's DSN points at
	Inject         Inject   `json:"inject"`                   // credential injection scheme
	Deny           []Rule   `json:"deny,omitempty"`           // HTTP method/path deny rules
	DenyStatements []string `json:"denyStatements,omitempty"` // DB statement deny list (DB protocols)
}

// Inject is the pluggable credential scheme. SecretKey/Dummy/AccessKeyID/... are
// NAMES of other secrets in the same app/environment, resolved by the proxy at
// request time.
type Inject struct {
	Scheme    string `json:"scheme"`             // bearer | basic | x-api-key | pg-handshake | aws-sigv4
	SecretKey string `json:"secretKey"`          // secret holding the live credential
	Dummy     string `json:"dummy,omitempty"`    // secret holding the dummy placeholder the agent uses
	Header    string `json:"header,omitempty"`   // header name for x-api-key (default X-Api-Key)
	User      string `json:"user,omitempty"`     // DB user (DB protocols)
	Database  string `json:"database,omitempty"` // DB name (DB protocols)

	// AWS SigV4 (scheme "aws-sigv4"): NAMES of the secrets holding the live IAM
	// credential. All optional — they default to the conventional key names
	// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_IAM_USERNAME).
	AccessKeyID     string `json:"accessKeyId,omitempty"`     // live access key id
	SecretAccessKey string `json:"secretAccessKey,omitempty"` // live secret access key
	Username        string `json:"username,omitempty"`        // IAM username (informational; injected as-is)
	SessionToken    string `json:"sessionToken,omitempty"`    // live session token (only for STS/temporary creds; omit for IAM-user keys)
}

type Rule struct {
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

// AgentEnv returns the environment entries an agent needs to USE this binding —
// the dummy placeholder(s) it should hold. The proxy swaps/re-signs them for the
// live credential upstream, so nothing here is sensitive. Scheme-aware so every
// caller (run/connect/get config/start) emits the same, correct variables.
func (b *Binding) AgentEnv(secrets map[string]string) map[string]string {
	env := map[string]string{}
	if isAWSSigV4(b.Inject.Scheme) {
		// Only the SECRET access key is actually secret and must be faked; the proxy
		// re-signs with the live key upstream. The access key id and IAM username are
		// NON-secret identifiers (they appear in ARNs, sts get-caller-identity,
		// CloudTrail) — inject the REAL values so tools don't choke on a bogus id and
		// the agent isn't misled about the identity it's acting as.
		akidName, _, userName, _ := awsSecretNames(b.Inject)
		akid := secrets[akidName]
		if akid == "" {
			akid = awsDummyAccessKeyID // fallback keeps the client on env creds, not ambient ~/.aws
		}
		env["AWS_ACCESS_KEY_ID"] = akid
		env["AWS_SECRET_ACCESS_KEY"] = awsDummySecretAccessKey // the only real secret — always a dummy
		if u := secrets[userName]; u != "" {
			env["AWS_IAM_USERNAME"] = u
		}
		return env
	}
	// Default (bearer/basic/x-api-key): the agent holds the dummy under the same
	// env var name the tool expects the live credential in.
	if b.Inject.Dummy != "" && b.Inject.SecretKey != "" {
		if d := secrets[b.Inject.Dummy]; d != "" {
			env[b.Inject.SecretKey] = d
		}
	}
	return env
}

// BuildConfig discovers provider bindings from the fetched secret map.
func BuildConfig(secrets map[string]string) (*Config, error) {
	cfg := &Config{}
	for name, val := range secrets {
		if !strings.HasSuffix(name, policySuffix) || len(name) == len(policySuffix) {
			continue
		}
		var b Binding
		if err := json.Unmarshal([]byte(val), &b); err != nil {
			return nil, fmt.Errorf("invalid %s JSON: %w", name, err)
		}
		b.Provider = strings.TrimSuffix(name, policySuffix)
		if b.Host == "" {
			return nil, fmt.Errorf(`%s: missing "host"`, name)
		}
		if b.Protocol == "" {
			b.Protocol = "http"
		}
		cfg.Bindings = append(cfg.Bindings, b)
	}
	if len(cfg.Bindings) == 0 {
		return nil, fmt.Errorf("no *_POLICY secrets found in this app/environment — add a provider folder (e.g. /github with GITHUB_POLICY)")
	}
	return cfg, nil
}

// httpBindingFor returns the HTTP binding governing host, if any.
func (c *Config) httpBindingFor(host string) *Binding {
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if b.Protocol == "http" && hostMatch(b.Host, host) {
			return b
		}
	}
	return nil
}

// dbBindingFor returns the DB binding whose upstream is hostport (transparent
// mode routes by SO_ORIGINAL_DST host:port).
func (c *Config) dbBindingFor(hostport string) *Binding {
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if b.Protocol == "" || b.Protocol == "http" {
			continue
		}
		if strings.EqualFold(b.Host, hostport) {
			return b
		}
	}
	return nil
}

// hostMatch does case-insensitive exact match, with optional leading "*." wildcard.
func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return false
}

// AgentEnv renders the environment an agent runtime sources: route through the
// proxy, trust its CA, and use the DUMMY placeholder values. It contains NO
// Phase token and NO live credentials — the agent can never reach real secrets.
// AgentEnviron returns the environment entries ("KEY=VALUE") an agent needs:
// proxy routing + CA trust (set under as many runtime-specific var names as
// possible so any tool/SDK/CLI is covered) + the DUMMY placeholder values.
// Contains NO Phase token and NO live credentials.
func AgentEnviron(cfg *Config, secrets map[string]string, proxyURL, caPath string, includeProxy bool) []string {
	var env []string
	if includeProxy {
		// In transparent mode the OS routes egress, so proxy vars are omitted
		// (and none can be unset to bypass it). Otherwise set every common form.
		env = append(env,
			"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL,
			"HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL,
			"ALL_PROXY="+proxyURL, "all_proxy="+proxyURL,
		)
	}
	env = append(env,
		"SSL_CERT_FILE="+caPath,        // OpenSSL, curl, Go (explicit), many CLIs
		"CURL_CA_BUNDLE="+caPath,       // curl
		"REQUESTS_CA_BUNDLE="+caPath,   // Python requests / botocore
		"NODE_EXTRA_CA_CERTS="+caPath,  // Node.js
		"GIT_SSL_CAINFO="+caPath,       // git
		"AWS_CA_BUNDLE="+caPath,        // AWS SDKs / CLI
		"CODEX_CA_CERTIFICATE="+caPath, // Codex CLI (Rust/rustls)
	)
	for i := range cfg.Bindings {
		for k, v := range cfg.Bindings[i].AgentEnv(secrets) {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func AgentEnv(cfg *Config, secrets map[string]string, proxyURL, caPath string, transparent bool) string {
	var b strings.Builder
	b.WriteString("# Phase egress proxy — agent runtime environment.\n")
	b.WriteString("# Dummy placeholders only; the proxy swaps them for live creds. No Phase token here.\n")
	for _, e := range AgentEnviron(cfg, secrets, proxyURL, caPath, !transparent) {
		fmt.Fprintf(&b, "export %s\n", e)
	}
	return b.String()
}
