package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel/control"
	"github.com/phasehq/cli/internal/tunnel/engine"
	"github.com/phasehq/cli/internal/tunnel/helper"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "🚇 Send this machine's traffic through Phase",
	Long: "Send this machine's traffic through Phase, with no proxy settings in any program. " +
		"Traffic for your Connections' hosts goes to the Phase credential proxy, which swaps decoys for real credentials. " +
		"Everything else passes through unread. Your local network and other VPNs, such as Tailscale, keep their own routes. " +
		"The first run installs a small helper, which asks for your password once.",
	Args: cobra.NoArgs,
	RunE: runUp,
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop sending this machine's traffic through Phase",
	Args:  cobra.NoArgs,
	RunE:  runDown,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show what phase up is doing",
	Args:  cobra.NoArgs,
	RunE:  runStatus,
}

func init() {
	upCmd.Flags().String("workflow", "", "Agent Workflow whose Connections to use, for a user login (defaults to the one set with phase ai enable)")
	upCmd.Flags().Bool("reinstall-helper", false, "Install the helper again, even if it's current")
	downCmd.Flags().Bool("uninstall", false, "Also remove the helper")
	rootCmd.AddCommand(upCmd, downCmd, statusCmd)
}

func runUp(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if !helper.Supported() {
		return errors.New("phase up is only available on macOS for now")
	}
	if os.Geteuid() == 0 {
		return errors.New("run phase up as yourself, not with sudo; it asks for your password when it needs it")
	}
	workflow, _ := cmd.Flags().GetString("workflow")
	runtimeInstance, err := airuntime.NewForUp(workflow)
	if err != nil {
		return err
	}
	if runtimeInstance.Client.TokenType() != agentapi.TokenAgent && runtimeInstance.WorkflowID == "" {
		return errors.New("phase up needs an Agent Workflow for a user login: pass --workflow, or log in with an Agent token")
	}
	directory, err := tunnelStateDirectory()
	if err != nil {
		return err
	}
	interactive := term.IsTerminal(int(os.Stdin.Fd()))

	fmt.Fprintln(out, "🔐 Certificate")
	if err := ensureTunnelCATrust(out); err != nil {
		return err
	}

	fmt.Fprintln(out, "\n🛡️  Helper")
	reinstall, _ := cmd.Flags().GetBool("reinstall-helper")
	if err := ensureTunnelHelper(out, interactive, reinstall); err != nil {
		return err
	}

	fmt.Fprintln(out, "\n🚇 Tunnel")
	if pid, running := tunnelEnginePID(directory); running {
		fmt.Fprintf(out, "   The engine is already running (pid %d).\n", pid)
	} else {
		pid, err := startTunnelEngine(directory, workflow)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "   Started the engine as you (pid %d). It holds the credentials, and the helper never sees them.\n", pid)
	}
	status, err := waitForCapture(directory, 45*time.Second)
	if err != nil {
		return err
	}
	engineStatus, _ := engine.ReadStatus(directory)
	fmt.Fprintf(out, "   ✅ Everything on this Mac now goes through Phase, by %s.\n", status.Device)
	if len(engineStatus.Connections) > 0 {
		fmt.Fprintf(out, "   Connections: %s\n", strings.Join(engineStatus.Connections, ", "))
	}
	fmt.Fprintln(out, "   Your local network and other VPNs, such as Tailscale, keep their own routes.")
	fmt.Fprintln(out, "   If the engine stops, Phase steps aside and your network works as it did before.")

	fmt.Fprintln(out, "\nNext steps")
	fmt.Fprintln(out, "   phase status   see what's going through Phase")
	fmt.Fprintln(out, "   phase down     stop")
	return nil
}

var errTunnelNeedsKeystore = errors.New("phase up needs a system keystore to keep its certificate authority's key, and none is usable here; your network is unchanged")

// ensureTunnelCATrust makes sure programs accept the proxy's certificates for
// Connection hosts. It's the same certificate authority Phase AI uses.
func ensureTunnelCATrust(out io.Writer) error {
	// Programs behind the tunnel get no certificate settings of their own, so they
	// can only trust a certificate authority that lasts and sits in the trust store.
	// One whose key is kept in memory is new in every process, the engine's included.
	if !aiCAStore.KeystoreAvailable() {
		return errTunnelNeedsKeystore
	}
	_, paths, err := aiCAStore.Ensure()
	if err != nil {
		return fmt.Errorf("prepare Phase's certificate authority: %w", err)
	}
	if paths.MemoryOnly {
		// The keystore answered, but wouldn't keep the key.
		return errTunnelNeedsKeystore
	}
	if tool := phaseproxy.UserCATrustAvailability(goruntime.GOOS); tool != nil {
		return fmt.Errorf("trust Phase's certificate authority: %s", phaseproxy.UserCATrustToolHint(tool))
	}
	if notice := phaseproxy.UserCATrustNotice(goruntime.GOOS); notice != "" && !caTrusted(paths.Certificate) {
		fmt.Fprintln(out, "   Programs need to trust Phase's certificate authority for your Connections' hosts.")
		fmt.Fprintln(out, "   "+notice)
	}
	result, err := phaseproxy.TrustCAForCurrentUser(paths.Certificate)
	if err != nil {
		return fmt.Errorf("trust Phase's certificate authority: %w", err)
	}
	if result.AlreadyTrusted {
		fmt.Fprintf(out, "   ✅ Phase's certificate authority is trusted in the %s.\n", result.Store)
	} else {
		fmt.Fprintf(out, "   ✅ Trusted Phase's certificate authority in the %s.\n", result.Store)
	}
	return nil
}

// caTrusted is a quick check, so the notice only appears when a dialog will.
func caTrusted(certificate string) bool {
	if goruntime.GOOS != "darwin" {
		return false
	}
	return exec.Command("/usr/bin/security", "verify-cert", "-c", certificate, "-p", "ssl").Run() == nil
}

func ensureTunnelHelper(out io.Writer, interactive, reinstall bool) error {
	reply, err := control.Ask(helper.SocketPath, control.Request{Op: control.OpStatus}, 5*time.Second)
	current := err == nil && reply.Status != nil && reply.Status.Protocol == control.ProtocolVersion
	if current && !reinstall {
		fmt.Fprintln(out, "   ✅ The Phase helper is installed and running.")
		return nil
	}
	if !interactive {
		return errors.New("the Phase helper isn't installed: run phase up in a terminal once, so it can ask for your password")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if current || helper.Installed() {
		fmt.Fprintln(out, "   Updating the Phase helper.")
	} else {
		fmt.Fprintln(out, "   Installing the Phase helper. It's the one part that needs root: it owns the tunnel")
		fmt.Fprintln(out, "   device and routes, and never sees a credential.")
	}
	fmt.Fprintln(out, "   macOS will ask for your password now.")
	install := exec.Command("sudo", "-p", "   Password: ", self, "tunnel", "install", "--uid", strconv.Itoa(os.Getuid()))
	install.Stdin, install.Stdout, install.Stderr = os.Stdin, out, os.Stderr
	if err := install.Run(); err != nil {
		return fmt.Errorf("install the Phase helper: %w", err)
	}
	fmt.Fprintln(out, "   ✅ Installed. It starts with your Mac, and does nothing until phase up.")
	return nil
}

func tunnelEnginePIDPath(directory string) string { return filepath.Join(directory, "engine.pid") }

// tunnelEnginePID finds a running engine, checking the process really is one.
func tunnelEnginePID(directory string) (int, bool) {
	content, err := os.ReadFile(tunnelEnginePIDPath(directory))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || !processIsAlive(pid) {
		return 0, false
	}
	command, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil || !strings.Contains(string(command), "tunnel engine") {
		return 0, false
	}
	return pid, true
}

func startTunnelEngine(directory, workflow string) (int, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return 0, err
	}
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	logFile, err := os.OpenFile(filepath.Join(directory, "engine.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()
	args := []string{"tunnel", "engine"}
	if workflow != "" {
		args = append(args, "--workflow", workflow)
	}
	command := exec.Command(self, args...)
	command.Stdout, command.Stderr = logFile, logFile
	configureDetachedProcess(command)
	if err := command.Start(); err != nil {
		return 0, fmt.Errorf("start the engine: %w", err)
	}
	pid := command.Process.Pid
	_ = command.Process.Release()
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return pid, err
	}
	return pid, nil
}

// waitForCapture waits for the helper to say it's capturing, and explains what went
// wrong if it doesn't.
func waitForCapture(directory string, wait time.Duration) (control.Status, error) {
	deadline := time.Now().Add(wait)
	var last control.Status
	for time.Now().Before(deadline) {
		if reply, err := control.Ask(helper.SocketPath, control.Request{Op: control.OpStatus}, 5*time.Second); err == nil && reply.Status != nil {
			last = *reply.Status
			if last.Capturing {
				return last, nil
			}
		}
		if status, err := engine.ReadStatus(directory); err == nil && status.LastError != "" && !status.Ready {
			return last, fmt.Errorf("the engine couldn't start a session: %s", status.LastError)
		}
		if _, running := tunnelEnginePID(directory); !running {
			return last, fmt.Errorf("the engine stopped; see %s", filepath.Join(directory, "engine.log"))
		}
		time.Sleep(300 * time.Millisecond)
	}
	reason := last.Reason
	if reason == "" {
		reason = "no reason given"
	}
	return last, fmt.Errorf("Phase didn't start capturing (%s); your network is unchanged. Run phase status for details", reason)
}

func runDown(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if !helper.Supported() {
		return errors.New("phase up is only available on macOS for now")
	}
	directory, err := tunnelStateDirectory()
	if err != nil {
		return err
	}
	if _, err := control.Ask(helper.SocketPath, control.Request{Op: control.OpDown}, 15*time.Second); err == nil {
		fmt.Fprintln(out, "✅ Phase has stepped aside: your network works as it did before phase up.")
	}
	if pid, running := tunnelEnginePID(directory); running {
		if process, err := os.FindProcess(pid); err == nil {
			_ = process.Signal(syscall.SIGTERM)
			for range 50 {
				if !processIsAlive(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if processIsAlive(pid) {
				_ = process.Kill()
			}
		}
		fmt.Fprintln(out, "✅ Stopped the engine.")
	}
	_ = os.Remove(tunnelEnginePIDPath(directory))
	if uninstall, _ := cmd.Flags().GetBool("uninstall"); uninstall && helper.Installed() {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "Removing the Phase helper. macOS will ask for your password.")
		command := exec.Command("sudo", "-p", "Password: ", self, "tunnel", "uninstall")
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, out, os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("remove the Phase helper: %w", err)
		}
		fmt.Fprintln(out, "✅ Removed the Phase helper.")
	}
	return nil
}

func runStatus(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if !helper.Supported() {
		return errors.New("phase up is only available on macOS for now")
	}
	directory, err := tunnelStateDirectory()
	if err != nil {
		return err
	}
	reply, err := control.Ask(helper.SocketPath, control.Request{Op: control.OpStatus}, 5*time.Second)
	switch {
	case err != nil:
		fmt.Fprintln(out, "🚇 Phase isn't in the path: the helper isn't running. Run phase up to start.")
	case reply.Status.Capturing:
		fmt.Fprintf(out, "🚇 Everything goes through Phase, by %s, since %s.\n", reply.Status.Device, reply.Status.Since.Local().Format("15:04"))
	default:
		reason := reply.Status.Reason
		if reason == "" {
			reason = "phase up hasn't been run"
		}
		fmt.Fprintf(out, "🚇 Phase isn't in the path: %s.\n", reason)
		if !reply.Status.Retry.IsZero() && reply.Status.Retry.After(time.Now()) {
			fmt.Fprintf(out, "   It tries again at %s.\n", reply.Status.Retry.Local().Format("15:04:05"))
		}
	}
	pid, running := tunnelEnginePID(directory)
	status, statusErr := engine.ReadStatus(directory)
	if !running || statusErr != nil {
		fmt.Fprintln(out, "   Engine: not running.")
		return nil
	}
	fmt.Fprintf(out, "   Engine: running as you (pid %d), leaving by %s.\n", pid, status.Interface)
	if len(status.Connections) > 0 {
		fmt.Fprintf(out, "   Connections: %s\n", strings.Join(status.Connections, ", "))
	}
	if len(status.Domains) > 0 {
		fmt.Fprintf(out, "   Names sent to Phase: %s\n", strings.Join(status.Domains, ", "))
	}
	if status.LastError != "" {
		fmt.Fprintf(out, "   Last error: %s\n", status.LastError)
	}
	proxied := status.Counts["proxy"] + status.Counts["proxy_by_tls_name"] + status.Counts["postgres"]
	fmt.Fprintf(out, "   Flows: %d to Connection hosts, %d passed through unread.\n", proxied, status.Counts["tcp"]+status.Counts["udp"])
	return nil
}
