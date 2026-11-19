package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel"
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
		"The model traffic of the AI coding tools Phase knows is read for those tools' own processes, " +
		"so that a secret value Phase handed out is replaced before it reaches a model. " +
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
	// For trying phase up on part of the network before trusting it with all of it.
	upCmd.Flags().String("routes", "", "Networks to send through Phase in place of everything, such as 192.0.2.0/24,198.51.100.0/24")
	_ = upCmd.Flags().MarkHidden("routes")
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
	routesFlag, _ := cmd.Flags().GetString("routes")
	routes, err := parseTunnelRoutes(routesFlag)
	if err != nil {
		return err
	}
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
	// Two engines would take the helper from each other every second, and the
	// machine's routes with it.
	if description, attached := otherEngineAttached(directory); attached {
		return fmt.Errorf("%s is attached to the Phase helper, and isn't the engine phase up started. Run phase down first, then phase up again", description)
	}
	if pid, running := tunnelEnginePID(directory); running {
		// A running engine keeps the routes it started with.
		if current, err := engine.ReadStatus(directory); err == nil && !sameTunnelRoutes(current.Routes, routes) {
			return errors.New("phase up is already running, and captures something else; run phase down first, then phase up again")
		}
		fmt.Fprintf(out, "   The engine is already running (pid %d).\n", pid)
	} else {
		pid, err := startTunnelEngine(directory, workflow, routes)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "   Started the engine as you (pid %d). It holds the credentials, and the helper never sees them.\n", pid)
	}
	// From here phase up ends in one of two ways: Phase is capturing, and says so, or
	// nothing is left running. An engine left to keep trying would start capturing
	// later, with nobody told. Ctrl-C while waiting is the second way too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	status, err := waitForCapture(ctx, directory, 45*time.Second)
	if err != nil {
		return abandonUp(directory, err)
	}
	engineStatus, _ := engine.ReadStatus(directory)
	printUpResult(out, status, engineStatus)
	return nil
}

// printUpResult says what phase up has done, once Phase is capturing. It claims
// nothing the tunnel doesn't do: a connection that was open before keeps the path it
// had, and what goes through Phase is read only where status says so.
func printUpResult(out io.Writer, status control.Status, engineStatus engine.Status) {
	if capturesEverything(status.Routes) {
		fmt.Fprintf(out, "   ✅ New connections on this Mac now go through Phase, by %s.\n", status.Device)
	} else {
		fmt.Fprintf(out, "   ✅ New connections to %s, and to the names sent to Phase, now go through it, by %s. Everything else is untouched.\n", strings.Join(status.Routes, ", "), status.Device)
	}
	fmt.Fprintln(out, "   Connections that were already open stay as they are.")
	if len(engineStatus.Connections) > 0 {
		fmt.Fprintf(out, "   Connections: %s\n", strings.Join(engineStatus.Connections, ", "))
	}
	if tools := readToolNames(&engineStatus); len(tools) > 0 {
		fmt.Fprintf(out, "   Model traffic is read for %s, each for its own processes only.\n", strings.Join(tools, ", "))
	}
	fmt.Fprintln(out, "   Your local network and other VPNs, such as Tailscale, keep their own routes.")
	fmt.Fprintln(out, "   If the engine stops, Phase steps aside and your network works as it did before.")

	fmt.Fprintln(out, "\nNext steps")
	fmt.Fprintln(out, "   phase status   see what's going through Phase")
	fmt.Fprintln(out, "   phase down     stop")
}

// abandonUp ends a phase up that didn't get to Phase capturing. It stops the tunnel
// as phase down does, so that nothing keeps trying and captures later, and says what
// is true of the machine afterwards.
func abandonUp(directory string, cause error) error {
	pid, running := tunnelEnginePID(directory)
	stopped := stopTunnel(directory)
	var left []string
	if running && processIsAlive(pid) {
		left = append(left, fmt.Sprintf("the engine (pid %d) couldn't be stopped", pid))
	}
	if stopped.stillAttached != "" {
		left = append(left, stopped.stillAttached+" is still attached to the helper, and can bring Phase back")
	}
	if !stopped.steppedAside {
		left = append(left, "the helper didn't answer when asked to step aside")
	}
	log := filepath.Join(directory, "engine.log")
	if len(left) == 0 {
		return fmt.Errorf("%w. phase up has stopped: the engine isn't running and Phase isn't in the path, so your network is as it was before. The engine's log is %s", cause, log)
	}
	return fmt.Errorf("%w. phase up has stopped, but %s. Run phase status, and phase down again, before you rely on the network being as it was. The engine's log is %s", cause, strings.Join(left, ", and "), log)
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
	reply, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpStatus}, 5*time.Second)
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

func startTunnelEngine(directory, workflow string, routes []string) (int, error) {
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
	if len(routes) > 0 {
		args = append(args, "--routes", strings.Join(routes, ","))
	}
	command := exec.Command(self, args...)
	command.Stdout, command.Stderr = logFile, logFile
	configureDetachedProcess(command)
	if err := command.Start(); err != nil {
		return 0, fmt.Errorf("start the engine: %w", err)
	}
	pid := command.Process.Pid
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		// Without its pid on record nothing could find the engine to stop it.
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return 0, fmt.Errorf("record the engine's process: %w", err)
	}
	_ = command.Process.Release()
	return pid, nil
}

// waitForCapture waits for the helper to say it's capturing, and says why when it
// doesn't. It says nothing of what is left running: whoever called it sees to that.
func waitForCapture(ctx context.Context, directory string, wait time.Duration) (control.Status, error) {
	deadline := time.Now().Add(wait)
	var last control.Status
	for time.Now().Before(deadline) {
		if reply, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpStatus}, 5*time.Second); err == nil && reply.Status != nil {
			last = *reply.Status
			if last.Capturing {
				return last, nil
			}
		}
		if status, err := engine.ReadStatus(directory); err == nil && status.LastError != "" && !status.Ready {
			return last, fmt.Errorf("the engine couldn't start a session: %s", status.LastError)
		}
		if _, running := tunnelEnginePID(directory); !running {
			return last, errors.New("the engine stopped before Phase started capturing")
		}
		select {
		case <-ctx.Done():
			return last, errors.New("phase up was interrupted before Phase started capturing")
		case <-time.After(300 * time.Millisecond):
		}
	}
	reason := last.Reason
	if reason == "" {
		reason = "no reason given"
	}
	return last, fmt.Errorf("Phase didn't start capturing (%s)", reason)
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
	stopped := stopTunnel(directory)
	if stopped.steppedAside {
		fmt.Fprintln(out, "✅ Phase has stepped aside: your network works as it did before phase up.")
	}
	if stopped.stoppedEngine {
		fmt.Fprintln(out, "✅ Stopped the engine.")
	}
	if stopped.stoppedOther != 0 {
		fmt.Fprintf(out, "✅ Stopped another engine that was attached to the helper (pid %d).\n", stopped.stoppedOther)
	}
	if stopped.stillAttached != "" {
		// Not Phase's to stop: it brings Phase back within a second of this.
		fmt.Fprintf(out, "⚠️  %s is still attached to the helper, and isn't an engine of yours that phase down may stop. It brings Phase back until it is stopped.\n", stopped.stillAttached)
	}
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

// tunnelStop is what stopping the tunnel did.
type tunnelStop struct {
	// steppedAside is the helper's own word that it has stepped aside.
	steppedAside bool
	// stoppedEngine is the engine phase up started and kept the pid of.
	stoppedEngine bool
	// stoppedOther is another engine that was attached to the helper, and was
	// stopped too. stillAttached describes one that wasn't Phase's to stop.
	stoppedOther  int
	stillAttached string
}

// stopTunnel asks the helper to step aside, then stops the engine. It reports what
// it did.
//
// The helper lets go of an engine it steps aside for, and an engine that is still
// running attaches again within a second. So the engine the helper has attached is
// stopped as well as the one phase up kept the pid of: they differ when an engine
// was started some other way. Only a process of this user's that is a phase binary
// running the engine is stopped. Anything else is left alone and named.
func stopTunnel(directory string) tunnelStop {
	var stopped tunnelStop
	attached := 0
	if tunnelHelperSocket != "" {
		// Asked first: once it has let go of an engine, the helper no longer knows it.
		if reply, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpStatus}, 5*time.Second); err == nil && reply.Status != nil && reply.Status.Attached {
			attached = reply.Status.EnginePID
		}
		_, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpDown}, 15*time.Second)
		stopped.steppedAside = err == nil
	}
	pid, running := tunnelEnginePID(directory)
	if running {
		stopTunnelProcess(pid)
		stopped.stoppedEngine = true
	}
	if attached > 0 && attached != pid && attached != os.Getpid() && processIsAlive(attached) {
		if description, ours := tunnelEngineProcess(attached); ours {
			stopTunnelProcess(attached)
			stopped.stoppedOther = attached
		} else {
			stopped.stillAttached = description
		}
	}
	_ = os.Remove(tunnelEnginePIDPath(directory))
	// An engine that stops when asked takes its proxy's state with it. One that had
	// to be killed leaves the state behind, naming a proxy that is gone.
	if state, err := engine.ReadProxyState(directory); err != nil || !processIsAlive(state.PID) {
		_ = os.Remove(engine.ProxyStatePath(directory))
	}
	return stopped
}

// otherEngineAttached reports an engine that is attached to the helper and isn't the
// one phase up started and kept the pid of, with what it is.
func otherEngineAttached(directory string) (description string, attached bool) {
	if tunnelHelperSocket == "" {
		return "", false
	}
	reply, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpStatus}, 5*time.Second)
	if err != nil || reply.Status == nil || !reply.Status.Attached || reply.Status.EnginePID <= 0 {
		return "", false
	}
	other := reply.Status.EnginePID
	if pid, running := tunnelEnginePID(directory); (running && pid == other) || !processIsAlive(other) {
		return "", false
	}
	description, _ = tunnelEngineProcess(other)
	return description, true
}

// stopTunnelProcess asks an engine to stop, and kills it if it hasn't after five
// seconds.
func stopTunnelProcess(pid int) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = process.Signal(syscall.SIGTERM)
	for range 50 {
		if !processIsAlive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = process.Kill()
	for range 20 {
		if !processIsAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// tunnelEngineProcess says what the process attached to the helper is, and whether
// it is an engine phase down may stop.
func tunnelEngineProcess(pid int) (description string, ours bool) {
	listing, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "uid=", "-o", "command=").Output()
	if err != nil {
		return fmt.Sprintf("process %d", pid), false
	}
	return describeEngineProcess(pid, string(listing), os.Getuid())
}

// describeEngineProcess reads one line of ps: the process's user, then its command
// line. The process is an engine phase down may stop when it is this user's, and its
// command line is a program whose name starts with phase, followed by tunnel engine.
// The description names the program and nothing else of the command line.
func describeEngineProcess(pid int, listing string, user int) (description string, ours bool) {
	owner, command, _ := strings.Cut(strings.TrimSpace(listing), " ")
	command = strings.TrimSpace(command)
	program, rest, engineCommand := strings.Cut(command, " tunnel engine")
	if !engineCommand || (rest != "" && !strings.HasPrefix(rest, " ")) {
		// Not the engine's command line: the program is its first word.
		program, _, _ = strings.Cut(command, " ")
		engineCommand = false
	}
	name := filepath.Base(program)
	if program == "" {
		name = "an unnamed program"
	}
	description = fmt.Sprintf("%s (process %d)", name, pid)
	uid, err := strconv.Atoi(owner)
	return description, err == nil && uid == user && engineCommand && strings.HasPrefix(name, "phase")
}

// parseTunnelRoutes reads the networks to send through Phase in place of everything.
// None means everything, and so do the routes that capture everything, written out.
func parseTunnelRoutes(value string) ([]string, error) {
	var routes []string
	seen := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("--routes: %q isn't a network, such as 192.0.2.0/24", part)
		}
		// Capturing everything takes each half of the address space and leaves the
		// default route alone, which the local network and other VPNs depend on.
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("--routes: %s would replace the default route; leave --routes out to send everything through Phase", part)
		}
		route := prefix.Masked().String()
		if !seen[route] {
			seen[route] = true
			routes = append(routes, route)
		}
	}
	if capturesEverything(routes) {
		return nil, nil
	}
	return routes, nil
}

// capturesEverything reports whether routes are the ones that send everything through
// Phase. No routes means the same: it's what the helper takes them to be.
func capturesEverything(routes []string) bool {
	return len(routes) == 0 || sameTunnelRoutes(routes, tunnel.FullRoutes)
}

// sameTunnelRoutes compares two sets of routes, where none means everything.
func sameTunnelRoutes(left, right []string) bool {
	normal := func(routes []string) string {
		if len(routes) == 0 {
			routes = tunnel.FullRoutes
		}
		sorted := append([]string(nil), routes...)
		sort.Strings(sorted)
		return strings.Join(sorted, ",")
	}
	return normal(left) == normal(right)
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
	var helperStatus *control.Status
	if reply, err := control.Ask(tunnelHelperSocket, control.Request{Op: control.OpStatus}, 5*time.Second); err == nil {
		helperStatus = reply.Status
	}
	var engineStatus *engine.Status
	pid, running := tunnelEnginePID(directory)
	if status, err := engine.ReadStatus(directory); running && err == nil {
		engineStatus = &status
	}
	printTunnelStatus(out, helperStatus, pid, engineStatus, time.Now())
	return nil
}

// printTunnelStatus writes what phase status shows. A helper or an engine that isn't
// running is nil.
func printTunnelStatus(out io.Writer, helperStatus *control.Status, pid int, status *engine.Status, now time.Time) {
	switch {
	case helperStatus == nil:
		fmt.Fprintln(out, "🚇 Phase isn't in the path: the helper isn't running. Run phase up to start.")
	case helperStatus.Capturing && capturesEverything(helperStatus.Routes):
		fmt.Fprintf(out, "🚇 Connections opened since %s go through Phase, by %s.\n", helperStatus.Since.Local().Format("15:04"), helperStatus.Device)
	case helperStatus.Capturing:
		fmt.Fprintf(out, "🚇 Only connections to %s, and to the names sent to Phase, opened since %s go through it, by %s. Everything else is untouched.\n",
			strings.Join(helperStatus.Routes, ", "), helperStatus.Since.Local().Format("15:04"), helperStatus.Device)
	default:
		reason := helperStatus.Reason
		if reason == "" {
			reason = "phase up hasn't been run"
		}
		fmt.Fprintf(out, "🚇 Phase isn't in the path: %s.\n", reason)
		if !helperStatus.Retry.IsZero() && helperStatus.Retry.After(now) {
			fmt.Fprintf(out, "   It tries again at %s.\n", helperStatus.Retry.Local().Format("15:04:05"))
		}
	}
	if status == nil {
		fmt.Fprintln(out, "   Engine: not running.")
		return
	}
	fmt.Fprintf(out, "   Engine: running as you (pid %d), leaving by %s.\n", pid, status.Interface)
	if len(status.Connections) > 0 {
		fmt.Fprintf(out, "   Connections: %s\n", strings.Join(status.Connections, ", "))
	}
	if len(status.Domains) > 0 {
		fmt.Fprintf(out, "   Names sent to Phase: %s\n", strings.Join(status.Domains, ", "))
	}
	switch skipped := status.SkippedNames; {
	case skipped == 1:
		fmt.Fprintln(out, "   1 Connection host has a name a DNS entry can't hold, so it isn't captured by name: only by the name in a TLS hello, where its traffic goes through Phase.")
	case skipped > 1:
		fmt.Fprintf(out, "   %d Connection hosts have names a DNS entry can't hold, so they aren't captured by name: only by the name in a TLS hello, where their traffic goes through Phase.\n", skipped)
	}
	if status.LastError != "" {
		fmt.Fprintf(out, "   Last error: %s\n", status.LastError)
	}
	proxied := status.Counts["proxy"] + status.Counts["proxy_by_tls_name"] + status.Counts["postgres"]
	fmt.Fprintf(out, "   Flows: %d to Connection hosts, %d passed through unread.\n", proxied, status.Counts["tcp"]+status.Counts["udp"])
	if loops := status.Counts["loop_refused"]; loops > 0 {
		fmt.Fprintf(out, "   %d were refused because their route led back into Phase: another VPN's range, while that VPN is down.\n", loops)
	}
	if refused := status.Counts["control_refused"]; refused > 0 {
		fmt.Fprintf(out, "   %d requests to %s were refused because they named another host.\n", refused, tunnel.ControlHost)
	}
	printModelTraffic(out, status)
}

// readToolNames lists the tools whose model traffic is read, in order.
func readToolNames(status *engine.Status) []string {
	tools := make([]string, 0, len(status.ReadTools))
	for tool, hosts := range status.ReadTools {
		if len(hosts) > 0 {
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	return tools
}

// printModelTraffic says which tools' model traffic is read, and how many flows were.
// It names the tools and their model hosts, which come from Phase's own table. What
// any program on the machine did appears only as a count.
func printModelTraffic(out io.Writer, status *engine.Status) {
	tools := make([]string, 0, len(status.ReadTools))
	for tool, hosts := range status.ReadTools {
		if len(hosts) > 0 {
			tools = append(tools, fmt.Sprintf("%s (%s)", tool, strings.Join(hosts, ", ")))
		}
	}
	if len(tools) == 0 {
		fmt.Fprintln(out, "   Model traffic: not read.")
		return
	}
	sort.Strings(tools)
	fmt.Fprintf(out, "   Model traffic is read for each tool's own processes: %s\n", strings.Join(tools, "; "))
	fmt.Fprintf(out, "   Model flows: %d read, %d left unread for other programs, %d left unread because the program wasn't found in time.\n",
		status.Counts["read"], status.Counts["unread_not_tool"], status.Counts["owner_lookup_failed"])
	// The proxy turned the flow away, or couldn't keep what it was told about it.
	if missed := status.Counts["unread_no_proxy"] + status.Counts["unread_not_noted"]; missed > 0 {
		fmt.Fprintf(out, "   %d more went on unread because Phase's proxy couldn't take them.\n", missed)
	}
}
