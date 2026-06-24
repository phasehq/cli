package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/spf13/cobra"
)

var proxyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "🚦 Start the egress proxy",
	Long: "Authenticate to Phase, fetch the provider credentials/dummies/policies for the app & " +
		"environment, run the proxy, and write the agent provisioning file (~/.phase/proxy/agent.env).",
	RunE: runProxyStart,
}

func init() {
	proxyStartCmd.Flags().String("listen", "127.0.0.1:8080", "Listen address")
	proxyStartCmd.Flags().Bool("transparent", false, "Transparent mode: accept OS-redirected (iptables) connections, route by SNI (no client config)")
	proxyStartCmd.Flags().String("proxy-url", "", "Proxy URL agents connect to (default http://<listen>)")
	proxyStartCmd.Flags().String("env", "", "Environment name")
	proxyStartCmd.Flags().String("app", "", "Application name")
	proxyStartCmd.Flags().String("app-id", "", "Application ID")
	proxyStartCmd.Flags().Duration("refresh", 60*time.Second, "How often to re-fetch secrets from Phase (0 to disable)")
	proxyStartCmd.Flags().Bool("lockdown", false, "Egress allowlist: DENY hosts with no binding (default: pass them through)")
	proxyCmd.AddCommand(proxyStartCmd)
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	transparent, _ := cmd.Flags().GetBool("transparent")
	proxyURL, _ := cmd.Flags().GetString("proxy-url")
	appName, _ := cmd.Flags().GetString("app")
	envName, _ := cmd.Flags().GetString("env")
	appID, _ := cmd.Flags().GetString("app-id")
	refresh, _ := cmd.Flags().GetDuration("refresh")
	lockdown, _ := cmd.Flags().GetBool("lockdown")
	if proxyURL == "" {
		proxyURL = "http://" + listen
	}

	// Load the CA: private key from keyring, public cert from disk.
	keyPEM, err := keyring.GetProxyCAKey()
	if err != nil {
		return fmt.Errorf("proxy CA not found — run 'phase proxy init' first: %w", err)
	}
	certPEM, err := proxy.ReadCACert()
	if err != nil {
		return fmt.Errorf("proxy CA certificate not found — run 'phase proxy init' first: %w", err)
	}
	ca, err := proxy.LoadCA(certPEM, []byte(keyPEM))
	if err != nil {
		return err
	}

	// Resolve app/env and fetch provider config + credentials from Phase. The
	// proxy is the only holder of Phase auth; the agent never gets a token.
	appName, envName, appID = phase.GetConfig(appName, envName, appID)
	cfg, secrets, err := fetchProxyConfig(appName, envName, appID)
	if err != nil {
		return err
	}

	// Write the agent provisioning file (routing + CA bundle + dummy creds only).
	// Use the combined bundle so passthrough hosts (real certs) validate too.
	bundle, err := proxy.EnsureCABundle()
	if err != nil {
		return err
	}
	envPath, err := proxy.WriteAgentEnv(proxy.AgentEnv(cfg, secrets, proxyURL, bundle, transparent))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%s  app=%s env=%s\n", util.BoldGreen("✓ proxy config loaded from Phase"), appName, envName)
	for _, b := range cfg.Bindings {
		if b.Protocol == "http" {
			fmt.Fprintf(os.Stderr, "    %s → %s  (swap/inject %s)\n", b.Provider, b.Host, b.Inject.SecretKey)
		} else {
			fmt.Fprintf(os.Stderr, "    %s → %s  protocol=%s (not served in PoC)\n", b.Provider, b.Host, b.Protocol)
		}
	}
	fmt.Fprintf(os.Stderr, "  agent env → %s\n", envPath)
	fmt.Fprintf(os.Stderr, "  agents pick it up with:  %s\n\n", util.BoldWhite("source "+envPath))

	srv := proxy.NewServer(cfg, ca, secrets, listen, lockdown)
	if refresh > 0 {
		go refreshProxy(srv, appName, envName, appID, refresh)
	}
	// One L4 listener serves both explicit-proxy (CONNECT) and transparently
	// redirected (raw TLS/Postgres) clients — classification handles both.
	return srv.ListenAndServe()
}

func fetchProxyConfig(appName, envName, appID string) (*proxy.Config, map[string]string, error) {
	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return nil, nil, err
	}
	// Path "" fetches every folder (the per-provider layout).
	all, err := p.Get(sdk.GetOptions{EnvName: envName, AppName: appName, AppID: appID, Path: ""})
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string, len(all))
	for _, s := range all {
		m[s.Key] = s.Value
	}
	cfg, err := proxy.BuildConfig(m)
	if err != nil {
		return nil, nil, err
	}
	return cfg, m, nil
}

func refreshProxy(srv *proxy.Server, appName, envName, appID string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		cfg, secrets, err := fetchProxyConfig(appName, envName, appID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  proxy secret refresh failed (keeping previous): %v\n", err)
			continue
		}
		srv.UpdateSecrets(cfg, secrets)
	}
}
