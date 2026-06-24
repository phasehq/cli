package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

// proxyChain isolates our nat rules so uninstall can remove them cleanly.
const proxyChain = "PHASE_PROXY"

const profileScript = "/etc/profile.d/phase-proxy.sh"

var proxyInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "🧱 Enforce transparent egress at the OS level (requires sudo)",
	Long: "Force a confined user's outbound TLS through the proxy via iptables, trust the proxy CA " +
		"system-wide, and auto-deliver the dummy credentials to that user — so agents are governed " +
		"implicitly and cannot bypass the proxy. Run once with sudo, after 'phase proxy start'.",
	RunE: runProxyInstall,
}

var proxyUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "🧹 Remove the transparent egress enforcement (requires sudo)",
	RunE:  runProxyUninstall,
}

func init() {
	proxyInstallCmd.Flags().Int("uid", -1, "UID of the agent user to confine (its egress is forced through the proxy)")
	proxyInstallCmd.Flags().Int("port", 8080, "Local port the transparent proxy listens on")
	proxyUninstallCmd.Flags().Int("uid", -1, "UID that was confined by install")
	proxyCmd.AddCommand(proxyInstallCmd)
	proxyCmd.AddCommand(proxyUninstallCmd)
}

func runProxyInstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("transparent install is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root: sudo phase proxy install --uid <agent-uid>")
	}
	uid, _ := cmd.Flags().GetInt("uid")
	port, _ := cmd.Flags().GetInt("port")
	if uid < 0 {
		return fmt.Errorf("--uid is required: the agent user to confine (refusing to redirect the whole machine)")
	}
	p := fmt.Sprint(port)
	u := fmt.Sprint(uid)

	// 0. BREAK-GLASS: snapshot the current ruleset before touching anything.
	backup, err := backupIptables()
	if err != nil {
		return fmt.Errorf("could not snapshot iptables (aborting before any change): %w", err)
	}
	fmt.Fprintf(os.Stderr, "  iptables backup → %s\n", backup)

	// 1. Trust the proxy CA system-wide.
	if err := installCATrust(); err != nil {
		return fmt.Errorf("install CA trust: %w", err)
	}

	// 2. nat chain: redirect the confined uid's 443/80 to the local proxy.
	_ = run("iptables", "-t", "nat", "-N", proxyChain) // ok if it already exists
	_ = run("iptables", "-t", "nat", "-F", proxyChain)
	if err := run("iptables", "-t", "nat", "-A", proxyChain, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", p); err != nil {
		return err
	}
	if err := run("iptables", "-t", "nat", "-A", proxyChain, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", p); err != nil {
		return err
	}
	// Postgres (transparent capture). The proxy recovers the real DB via
	// SO_ORIGINAL_DST and governs it. (MySQL 3306 lands with the MySQL handler —
	// redirecting it before then would stall on its server-speaks-first greeting.)
	if err := run("iptables", "-t", "nat", "-A", proxyChain, "-p", "tcp", "--dport", "5432", "-j", "REDIRECT", "--to-ports", p); err != nil {
		return err
	}
	_ = run("iptables", "-t", "nat", "-D", "OUTPUT", "-m", "owner", "--uid-owner", u, "-j", proxyChain)
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", u, "-j", proxyChain); err != nil {
		return err
	}

	// 3. Block QUIC/HTTP3 (UDP 443) for the confined uid so it can't bypass the
	//    TCP-only proxy; clients fall back to TLS-over-TCP.
	_ = run("iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", u, "-p", "udp", "--dport", "443", "-j", "REJECT")
	_ = run("iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", u, "-p", "udp", "--dport", "443", "-j", "REJECT")

	// 4. Auto-deliver dummy creds + CA env to the confined user (login shells).
	if err := writeConfinedUserEnv(uid); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️  could not write agent env (%v); start the proxy first, then re-run install\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  agent env  → %s (uid %d login shells)\n", profileScript, uid)
	}

	fmt.Fprintf(os.Stderr, "\n%s\n", util.BoldGreen("✓ transparent egress enforced"))
	fmt.Fprintf(os.Stderr, "  uid %d: all outbound TLS → proxy :%d, QUIC blocked, dummy creds delivered\n", uid, port)
	fmt.Fprintf(os.Stderr, "  proxy CA trusted system-wide. INPUT chain untouched (console/SSH unaffected).\n")
	fmt.Fprintf(os.Stderr, "  Run the proxy as a DIFFERENT user (so it isn't redirected): %s\n\n", util.BoldWhite("phase proxy start --transparent"))
	fmt.Fprintf(os.Stderr, "%s\n", util.BoldYellowErr("Break-glass recovery (if egress misbehaves):"))
	fmt.Fprintf(os.Stderr, "  1. %s\n", util.BoldWhite(fmt.Sprintf("sudo phase proxy uninstall --uid %d", uid)))
	fmt.Fprintf(os.Stderr, "  2. full restore:  %s\n", util.BoldWhite("sudo iptables-restore < "+backup))
	fmt.Fprintf(os.Stderr, "  3. nuclear:       %s then %s\n", util.BoldWhite("sudo iptables -F && sudo iptables -t nat -F"), util.BoldWhite("sudo systemctl restart docker"))
	fmt.Fprintf(os.Stderr, "  4. last resort:   reboot — these rules are runtime-only and are NOT persisted.\n")
	return nil
}

func runProxyUninstall(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("transparent install is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root: sudo phase proxy uninstall --uid <agent-uid>")
	}
	uid, _ := cmd.Flags().GetInt("uid")
	if uid >= 0 {
		u := fmt.Sprint(uid)
		_ = run("iptables", "-t", "nat", "-D", "OUTPUT", "-m", "owner", "--uid-owner", u, "-j", proxyChain)
		_ = run("iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", u, "-p", "udp", "--dport", "443", "-j", "REJECT")
	}
	_ = run("iptables", "-t", "nat", "-F", proxyChain)
	_ = run("iptables", "-t", "nat", "-X", proxyChain)
	_ = os.Remove(profileScript)
	_ = removeCATrust()
	fmt.Fprintf(os.Stderr, "%s\n", util.BoldGreen("✓ transparent egress enforcement removed"))
	return nil
}

// backupIptables snapshots the full ruleset so the user can fully restore it.
func backupIptables() (string, error) {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return "", err
	}
	dir := "/var/lib/phase-proxy"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("iptables-backup-%d.rules", time.Now().Unix()))
	if err := os.WriteFile(path, out, 0600); err != nil {
		return "", err
	}
	return path, nil
}

// writeConfinedUserEnv embeds the operator's agent.env (dummy creds + CA paths,
// all non-secret) into a uid-scoped /etc/profile.d snippet so the confined
// agent user picks them up automatically on login.
func writeConfinedUserEnv(uid int) error {
	op := os.Getenv("SUDO_USER")
	if op == "" {
		return fmt.Errorf("SUDO_USER not set; run via sudo")
	}
	usr, err := user.Lookup(op)
	if err != nil {
		return err
	}
	envPath := filepath.Join(usr.HomeDir, ".phase", "proxy", "agent.env")
	content, err := os.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("read %s (run 'phase proxy start' first)", envPath)
	}
	script := fmt.Sprintf("# Managed by phase proxy install — agent guardrail env (dummy creds + CA).\n"+
		"if [ \"$(id -u)\" = \"%d\" ]; then\n%sfi\n", uid, string(content))
	return os.WriteFile(profileScript, []byte(script), 0644)
}

func installCATrust() error {
	cert, err := proxy.ReadCACert()
	if err != nil {
		return fmt.Errorf("read CA certificate (run 'phase proxy init' first): %w", err)
	}
	if _, err := exec.LookPath("update-ca-trust"); err == nil { // RHEL/Fedora
		if err := os.WriteFile("/etc/pki/ca-trust/source/anchors/phase-proxy.pem", cert, 0644); err != nil {
			return err
		}
		return run("update-ca-trust")
	}
	if _, err := exec.LookPath("update-ca-certificates"); err == nil { // Debian/Ubuntu
		if err := os.WriteFile("/usr/local/share/ca-certificates/phase-proxy.crt", cert, 0644); err != nil {
			return err
		}
		return run("update-ca-certificates")
	}
	return fmt.Errorf("no supported CA trust tool found (update-ca-trust or update-ca-certificates)")
}

func removeCATrust() error {
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		_ = os.Remove("/etc/pki/ca-trust/source/anchors/phase-proxy.pem")
		return run("update-ca-trust")
	}
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		_ = os.Remove("/usr/local/share/ca-certificates/phase-proxy.crt")
		return run("update-ca-certificates")
	}
	return nil
}

func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stderr = os.Stderr
	return c.Run()
}
