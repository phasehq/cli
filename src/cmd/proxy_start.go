package cmd

import (
	"fmt"
	"io"
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
	cfg, secrets, dynKeys, leases, err := fetchProxyConfigEx(appName, envName, appID, true)
	if err != nil {
		return err
	}
	dynamicSnapshot := snapshotDynamic(secrets, dynKeys)

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
	fmt.Fprintf(os.Stderr, "  agents pick it up with:  %s\n", util.BoldWhite("source "+envPath))
	logLeaseExpiry(os.Stderr, leases)
	fmt.Fprintln(os.Stderr)

	srv := proxy.NewServer(cfg, ca, secrets, listen, lockdown)
	if refresh > 0 {
		go refreshProxy(srv, appName, envName, appID, refresh, dynamicSnapshot)
	}
	// One L4 listener serves both explicit-proxy (CONNECT) and transparently
	// redirected (raw TLS/Postgres) clients — classification handles both.
	return srv.ListenAndServe()
}

func fetchProxyConfig(appName, envName, appID string) (*proxy.Config, map[string]string, error) {
	cfg, secrets, _, _, err := fetchProxyConfigEx(appName, envName, appID, true)
	return cfg, secrets, err
}

// leaseInfo is the expiry metadata for one dynamic-secret group's active lease.
type leaseInfo struct {
	Group     string
	ID        string
	ExpiresAt string // RFC3339
	TTL       int    // seconds
}

// fetchProxyConfigEx fetches the provider config + secret snapshot. When
// generateLeases is true, dynamic-secret providers (e.g. an AWS IAM group)
// materialize live values via a freshly generated lease; it also returns the set
// of dynamic keys (so the caller can preserve them across refreshes instead of
// minting a new lease every time) and the lease expiry metadata. When false, only
// static secrets are fetched (no dynamic API call, no lease churn, no leases).
func fetchProxyConfigEx(appName, envName, appID string, generateLeases bool) (*proxy.Config, map[string]string, map[string]bool, []leaseInfo, error) {
	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Path "" fetches every folder (the per-provider layout).
	all, err := p.Get(sdk.GetOptions{
		EnvName: envName, AppName: appName, AppID: appID, Path: "",
		Dynamic: generateLeases, Lease: generateLeases,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	m := make(map[string]string, len(all))
	dyn := map[string]bool{}
	leasesByID := map[string]leaseInfo{}
	for _, s := range all {
		m[s.Key] = s.Value
		if s.IsDynamic {
			dyn[s.Key] = true
			// One lease backs several keys (AKID/secret/username); dedupe by lease id.
			if s.LeaseID != "" {
				leasesByID[s.LeaseID] = leaseInfo{Group: s.DynamicGroup, ID: s.LeaseID, ExpiresAt: s.LeaseExpiresAt, TTL: s.LeaseTTL}
			}
		}
	}
	cfg, err := proxy.BuildConfig(m)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leases := make([]leaseInfo, 0, len(leasesByID))
	for _, li := range leasesByID {
		leases = append(leases, li)
	}
	return cfg, m, dyn, leases, nil
}

// logLeaseExpiry prints, per dynamic lease, when it expires and how long that is
// from now. There is NO auto-renew (yet): when a lease expires the proxy's creds
// go dead and it must be restarted to mint a fresh one.
func logLeaseExpiry(w io.Writer, leases []leaseInfo) {
	for _, li := range leases {
		if li.ExpiresAt == "" {
			fmt.Fprintf(w, "  🔑 %s: lease %s (no expiry reported)\n", li.Group, shortID(li.ID))
			continue
		}
		when := li.ExpiresAt
		remaining := ""
		if t, err := time.Parse(time.RFC3339, li.ExpiresAt); err == nil {
			when = t.Local().Format("15:04:05 MST")
			d := time.Until(t).Round(time.Second)
			if d > 0 {
				remaining = fmt.Sprintf(" (in %s)", d)
			} else {
				remaining = " (EXPIRED)"
			}
		}
		fmt.Fprintf(w, "  🔑 %s: lease %s expires %s%s — no auto-renew; restart the proxy to rotate\n",
			li.Group, shortID(li.ID), when, remaining)
	}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// snapshotDynamic captures the current values of the dynamic keys so a refresh
// can re-overlay them instead of minting a new lease.
func snapshotDynamic(secrets map[string]string, dynKeys map[string]bool) map[string]string {
	out := make(map[string]string, len(dynKeys))
	for k := range dynKeys {
		out[k] = secrets[k]
	}
	return out
}

// refreshProxy keeps STATIC secrets current (e.g. a rotated GitHub token) without
// re-minting dynamic leases: it re-fetches static-only and re-overlays the
// dynamic values captured at startup, so a dynamic AWS lease lives for the
// proxy's lifetime rather than churning a new IAM user every interval.
func refreshProxy(srv *proxy.Server, appName, envName, appID string, every time.Duration, dynamicSecrets map[string]string) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		cfg, secrets, _, _, err := fetchProxyConfigEx(appName, envName, appID, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  proxy secret refresh failed (keeping previous): %v\n", err)
			continue
		}
		for k, v := range dynamicSecrets { // preserve the startup lease
			secrets[k] = v
		}
		srv.UpdateSecrets(cfg, secrets)
	}
}
