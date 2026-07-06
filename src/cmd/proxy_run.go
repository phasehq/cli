package cmd

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var proxyRunCmd = &cobra.Command{
	Use:   "run -- <command>",
	Short: "🏃 Run a command/agent routed through the proxy (no sudo, no setup)",
	Long: "Launch a command with proxy routing, CA trust, and dummy credentials set in its environment, " +
		"so any tool it runs (CLI, SDK, agent) sends its traffic through the proxy. The command and its " +
		"children inherit it; nothing else on the machine is affected. Starts an ephemeral proxy " +
		"automatically (no separate 'phase proxy start' needed); pass --proxy-url to use a shared or " +
		"transparent/enforced listener instead.",
	Args: cobra.MinimumNArgs(1),
	RunE: runProxyRun,
}

// addProxyRunFlags registers the flags for the run command. Shared so the same
// command can live under both `phase proxy run` and `phase ai run`.
func addProxyRunFlags(c *cobra.Command) {
	c.Flags().String("proxy-url", "http://127.0.0.1:8080", "URL of the running proxy")
	c.Flags().String("env", "", "Environment name")
	c.Flags().String("app", "", "Application name")
	c.Flags().String("app-id", "", "Application ID")
	c.Flags().String("log-file", "", "Where to write proxy audit logs (default ~/.phase/proxy/proxy.log; '-' = stderr)")
}

func init() {
	addProxyRunFlags(proxyRunCmd)
	proxyCmd.AddCommand(proxyRunCmd)
}

func runProxyRun(cmd *cobra.Command, args []string) error {
	proxyURL, _ := cmd.Flags().GetString("proxy-url")
	appName, _ := cmd.Flags().GetString("app")
	envName, _ := cmd.Flags().GetString("env")
	appID, _ := cmd.Flags().GetString("app-id")

	// Keep proxy audit logs OFF the agent's terminal (they interleave with its
	// TUI). Default: a file you can `tail -f`. Pass --log-file - to keep stderr.
	logFile, _ := cmd.Flags().GetString("log-file")
	if logFile != "-" {
		if logFile == "" {
			logFile = filepath.Join(proxy.Dir(), "proxy.log")
		}
		_ = os.MkdirAll(filepath.Dir(logFile), 0700)
		if f, e := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); e == nil {
			log.SetOutput(f)
			defer f.Close()
		}
	}

	// Ensure a CA exists (auto-init) and build the combined trust bundle (system
	// roots + our CA) so the agent validates BOTH passthrough hosts (real certs)
	// and intercepted hosts (our MITM leaf).
	ca, err := ensureProxyCA()
	if err != nil {
		return err
	}
	bundle, err := proxy.EnsureCABundle()
	if err != nil {
		return err
	}

	appName, envName, appID = phase.GetConfig(appName, envName, appID)
	cfg, secrets, err := fetchProxyConfig(appName, envName, appID)
	if err != nil {
		return err
	}

	// If no proxy is already running at proxyURL, start an ephemeral embedded one
	// for the lifetime of this command — so `phase proxy run` works on its own,
	// with no separate `phase proxy start` (that's only needed for a shared or
	// transparent/enforced listener).
	if !proxyReachable(proxyURL) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		proxyURL = "http://" + ln.Addr().String()
		// denyUnbound=false: pass through hosts with no rule so the agent's own
		// traffic (e.g. its LLM API) keeps working; only bound hosts are intercepted.
		go func() { _ = proxy.NewServer(cfg, ca, secrets, ln.Addr().String(), false).Serve(ln) }()
	}

	// Build the child environment: inherit current env, then overlay our keys.
	overlay := proxyEnv(proxyURL, bundle, cfg, secrets)
	merged := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			merged[kv[:i]] = kv[i+1:]
		}
	}
	for k, v := range overlay {
		merged[k] = v
	}
	// Per-agent adapter: best-configure the specific agent (extra routing/CA env)
	// and surface its own sandbox-enforcement option, without forcing it.
	adapter := proxy.AdapterFor(args[0])
	if adapter != nil {
		for k, v := range adapter.Env() {
			merged[k] = v
		}
	}
	envSlice := make([]string, 0, len(merged))
	for k, v := range merged {
		envSlice = append(envSlice, k+"="+v)
	}

	fmt.Fprintf(os.Stderr, "🛡  routing %s through the Phase proxy (%s, %d cred var(s), CA trusted)\n",
		util.BoldWhite(strings.Join(args, " ")), proxyURL, countDummies(cfg, secrets))
	if logFile != "-" {
		fmt.Fprintf(os.Stderr, "   audit log → %s  (tail -f to watch)\n", logFile)
	}
	if adapter != nil {
		fmt.Fprintf(os.Stderr, "   agent: %s — %s\n", util.BoldWhite(adapter.Name), adapter.Note)
	}

	// Exec the command directly (args preserved) — never through a shell, which
	// would mangle quoting/boundaries for things like `run -- sh -c '...'`.
	c := exec.Command(args[0], args[1:]...)
	c.Env = envSlice
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

// proxyEnv returns the env overlay that maximizes the chance any tool/SDK/runtime
// routes through the proxy and trusts its CA. Coverage is broad but not total —
// notably Node (fetch/undici) and some SDKs ignore HTTP_PROXY; the runtime-agnostic
// guarantee is the OS-level redirect (phase proxy install / sandbox).
func proxyEnv(proxyURL, caPath string, cfg *proxy.Config, secrets map[string]string) map[string]string {
	env := map[string]string{
		// Proxy routing (both cases; honored by curl, Go, Python, most CLIs/SDKs).
		"HTTP_PROXY": proxyURL, "http_proxy": proxyURL,
		"HTTPS_PROXY": proxyURL, "https_proxy": proxyURL,
		"ALL_PROXY": proxyURL, "all_proxy": proxyURL,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
		// CA trust across runtimes (so the MITM leaf is accepted).
		"SSL_CERT_FILE":        caPath, // OpenSSL, curl, Go, Python ssl
		"REQUESTS_CA_BUNDLE":   caPath, // Python requests / botocore
		"CURL_CA_BUNDLE":       caPath, // curl
		"NODE_EXTRA_CA_CERTS":  caPath, // Node.js
		"GIT_SSL_CAINFO":       caPath, // git
		"AWS_CA_BUNDLE":        caPath, // AWS SDK / CLI
		"DENO_CERT":            caPath, // Deno
		"CODEX_CA_CERTIFICATE": caPath, // Codex CLI (Rust/rustls — ignores NODE_EXTRA_CA_CERTS)
	}
	// JVM tools ignore env proxies but read JAVA_TOOL_OPTIONS.
	if h, p, err := net.SplitHostPort(hostOf(proxyURL)); err == nil {
		env["JAVA_TOOL_OPTIONS"] = fmt.Sprintf("-Dhttp.proxyHost=%s -Dhttp.proxyPort=%s -Dhttps.proxyHost=%s -Dhttps.proxyPort=%s", h, p, h, p)
	}
	// The dummy placeholder(s) each tool sends; the proxy swaps or re-signs them
	// for the live value. Scheme-aware (bearer swap, AWS SigV4 re-sign, ...).
	for i := range cfg.Bindings {
		for k, v := range cfg.Bindings[i].AgentEnv(secrets) {
			env[k] = v
		}
	}
	// Database bindings (explicit per-port capture): point the agent's DB client
	// at the local listener with a DUMMY password; the proxy injects the real
	// credential upstream. libpq env + DATABASE_URL cover psql/pgx/most ORMs.
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		if b.Protocol != "postgres" || b.ListenPort == 0 {
			continue
		}
		port := fmt.Sprintf("%d", b.ListenPort)
		dummy, user, db := secrets[b.Inject.Dummy], b.Inject.User, b.Inject.Database
		env["PGHOST"], env["PGPORT"] = "127.0.0.1", port
		if user != "" {
			env["PGUSER"] = user
		}
		if db != "" {
			env["PGDATABASE"] = db
		}
		if dummy != "" {
			env["PGPASSWORD"] = dummy
		}
		env["DATABASE_URL"] = fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
			url.QueryEscape(user), url.QueryEscape(dummy), port, url.QueryEscape(db))
	}
	return env
}

func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil {
		return u.Host
	}
	return rawurl
}

func countDummies(cfg *proxy.Config, secrets map[string]string) int {
	n := 0
	for i := range cfg.Bindings {
		n += len(cfg.Bindings[i].AgentEnv(secrets))
	}
	return n
}

// proxyReachable reports whether something is already listening at proxyURL.
func proxyReachable(proxyURL string) bool {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", u.Host, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ensureProxyCA loads the CA from the keyring, generating + storing one on first
// use so `phase proxy run` works with no prior `phase proxy init`.
func ensureProxyCA() (*proxy.CA, error) {
	if keyPEM, err := keyring.GetProxyCAKey(); err == nil {
		if certPEM, cerr := proxy.ReadCACert(); cerr == nil {
			return proxy.LoadCA(certPEM, []byte(keyPEM))
		}
	}
	ca, certPEM, keyPEM, err := proxy.GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	if err := keyring.SetProxyCAKey(string(keyPEM)); err != nil {
		return nil, fmt.Errorf("store CA private key in keyring: %w", err)
	}
	if _, err := proxy.WriteCACert(certPEM); err != nil {
		return nil, err
	}
	return ca, nil
}
