package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var proxyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "📦 Get proxy resources",
}

var proxyGetConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "📋 Run the proxy in this shell and print a copyable config for already-running agents",
	Long: "Start the egress proxy in the foreground on a random local port and print the routing/CA/" +
		"dummy-credential environment as a copy-pasteable markdown block. Paste it into an agent that " +
		"is already running (Claude Code, Codex, Cursor, ...) so its shell commands route through the " +
		"proxy — no relaunch needed. The proxy runs in this shell until you Ctrl-C. Each run gets its " +
		"own port and its own credential lease, so separate runs never collide.",
	RunE: runProxyGetConfig,
}

func init() {
	proxyGetConfigCmd.Flags().String("listen", "127.0.0.1:0", "Listen address (default: a random free port)")
	proxyGetConfigCmd.Flags().String("env", "", "Environment name")
	proxyGetConfigCmd.Flags().String("app", "", "Application name")
	proxyGetConfigCmd.Flags().String("app-id", "", "Application ID")
	proxyGetConfigCmd.Flags().Duration("refresh", 60*time.Second, "How often to re-fetch static secrets from Phase (0 to disable)")
	proxyGetConfigCmd.Flags().Bool("lockdown", false, "Egress allowlist: DENY hosts with no binding (default: pass them through)")
	proxyGetConfigCmd.Flags().String("log-file", "", "Where to write proxy audit logs (default ~/.phase/proxy/proxy.log; '-' = stderr)")
	proxyGetCmd.AddCommand(proxyGetConfigCmd)
	proxyCmd.AddCommand(proxyGetCmd)
}

func runProxyGetConfig(cmd *cobra.Command, args []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	appName, _ := cmd.Flags().GetString("app")
	envName, _ := cmd.Flags().GetString("env")
	appID, _ := cmd.Flags().GetString("app-id")
	refresh, _ := cmd.Flags().GetDuration("refresh")
	lockdown, _ := cmd.Flags().GetBool("lockdown")
	logFile, _ := cmd.Flags().GetString("log-file")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)
	return serveProxyForeground(listen, appName, envName, appID, logFile, refresh, lockdown)
}

// serveProxyForeground binds a (by default random) local port, prints the agent
// config, and runs the proxy in the FOREGROUND until Ctrl-C. Each invocation is
// its own proxy on its own port with its own credential lease — no background
// daemons and no port collisions with previous runs. Shared by `get config` and
// (after approval) `connect`.
func serveProxyForeground(listen, appName, envName, appID, logFile string, refresh time.Duration, lockdown bool) error {
	// Audit logs go to a file by default so stdout stays a clean, copyable block.
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

	ca, err := ensureProxyCA()
	if err != nil {
		return err
	}
	bundle, err := proxy.EnsureCABundle()
	if err != nil {
		return err
	}

	cfg, secrets, dynKeys, leases, err := fetchProxyConfigEx(appName, envName, appID, true)
	if err != nil {
		return err
	}
	dynamicSnapshot := snapshotDynamic(secrets, dynKeys)

	// Bind before printing so the printed proxy URL is live (and reflects the real
	// port when --listen uses :0, which is the default).
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", listen, err)
	}
	proxyURL := "http://" + ln.Addr().String()

	fmt.Fprintf(os.Stderr, "%s  app=%s env=%s  listening on %s  (%d cred var(s))\n",
		util.BoldGreen("✓ proxy running"), appName, envName, proxyURL, countDummies(cfg, secrets))
	for _, b := range cfg.Bindings {
		fmt.Fprintf(os.Stderr, "    %s → %s  protocol=%s\n", b.Provider, b.Host, b.Protocol)
	}
	if logFile != "-" {
		fmt.Fprintf(os.Stderr, "  audit log → %s  (tail -f to watch)\n", logFile)
	}
	logLeaseExpiry(os.Stderr, leases)
	fmt.Fprintf(os.Stderr, "\n%s\n\n", util.BoldWhite("── copy the block below into your running agent ──"))

	fmt.Println(agentConfigMarkdown(proxyEnv(proxyURL, bundle, cfg, secrets)))

	fmt.Fprintf(os.Stderr, "\n%s\n", util.BoldWhite("── proxy on "+proxyURL+" — running in this shell ──"))
	fmt.Fprintf(os.Stderr, "   press %s to stop  ·  to background it: %s then %s\n",
		util.BoldWhite("Ctrl-C"), util.BoldWhite("Ctrl-Z"), util.BoldWhite("bg"))

	srv := proxy.NewServer(cfg, ca, secrets, ln.Addr().String(), lockdown)
	if refresh > 0 {
		go refreshProxy(srv, appName, envName, appID, refresh, dynamicSnapshot)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case s := <-sig:
		fmt.Fprintf(os.Stderr, "\n✋ %v — proxy stopped\n", s)
		return nil
	}
}

// agentConfigMarkdown renders the env overlay as a self-contained markdown
// snippet an agent (or human) can act on without any other context.
func agentConfigMarkdown(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("Route all shell commands through the Phase egress proxy: export these environment variables in every shell you run (or prefix each command with them). Secret values here are dummy placeholders — the proxy swaps in the live secret upstream. Non-secret identifiers (e.g. an AWS access key id or username) are real.\n\n")
	b.WriteString("```sh\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(env[k]))
	}
	b.WriteString("```")
	return b.String()
}

// shellQuote single-quotes s for POSIX shells (embedded ' becomes quoted-escape-requote).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
