package cmd

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

// A relay is the Phase AI credential proxy for Agent sandboxes that cannot run
// the Phase CLI themselves (cloud harness sandboxes, CI runners, remote dev
// boxes). It binds a non-loopback TLS listener, authenticates with an Agent
// token, keeps one proxy credential for its whole lifetime, and recycles its
// backend session in place. Sandboxes are bootstrapped with a single line.
const (
	relayDefaultListenAddress = "0.0.0.0:9543"
	relayMaxRetryDelay        = 30 * time.Second
)

var (
	relayNewRuntime    = airuntime.NewForRelay
	relayRetryDelayFor = relayRetryDelay
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "🛰️  Run a Phase AI relay for remote Agent sandboxes",
	Long: "A relay is a Phase AI credential proxy that remote Agent sandboxes reach over TLS. " +
		"It logs in with an Agent token, keeps its backend session fresh in place, and hands each sandbox a one-line bootstrap.",
}

var relayStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a relay on this machine",
	Long: "Start a Phase AI relay. Requires an Agent token login (phase auth --mode token) and a publicly trusted TLS certificate " +
		"for the advertised host, for example from `tailscale cert`. The proxy listens on port 9543; the PostgreSQL adapter " +
		"listens on port 9544 only when the Workflow has a PostgreSQL Connection.",
	Args: cobra.NoArgs,
	RunE: runRelayStart,
}

func init() {
	relayStartCmd.Flags().String("advertise-host", "", "DNS name sandboxes dial; the TLS certificate must cover it")
	relayStartCmd.Flags().String("tls-cert", "", "TLS certificate chain PEM for the advertised host")
	relayStartCmd.Flags().String("tls-key", "", "Owner-only TLS private key PEM")
	relayStartCmd.Flags().String("listen", relayDefaultListenAddress, "Proxy bind address; the PostgreSQL adapter binds the same host on the next port (9544 by default)")
	relayStartCmd.Flags().Bool("lockdown", false, "Block unbound hosts instead of passing them through")
	relayStartCmd.Flags().String("tls-ca", "", "PEM bundle of root certificates that issued --tls-cert, for private PKI; sandboxes must already trust it (defaults to the system trust store)")
	for _, name := range []string{"advertise-host", "tls-cert", "tls-key"} {
		_ = relayStartCmd.MarkFlagRequired(name)
	}
	relayCmd.AddCommand(relayStartCmd)
	rootCmd.AddCommand(relayCmd)
}

func runRelayStart(cmd *cobra.Command, _ []string) error {
	engine, err := relayEngineFromFlags(cmd)
	if err != nil {
		return err
	}
	if err := engine.Ready(); err != nil {
		return err
	}
	runtimeInstance, err := relayNewRuntime()
	if err != nil {
		return err
	}
	return runRelayLoop(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), runtimeInstance, engine)
}

func relayEngineFromFlags(cmd *cobra.Command) (*aiproxy.Engine, error) {
	listen, _ := cmd.Flags().GetString("listen")
	listen = strings.TrimSpace(listen)
	host, rawPort, err := net.SplitHostPort(listen)
	port, portErr := strconv.Atoi(rawPort)
	if err != nil || portErr != nil || port < 1 || port > 65534 {
		return nil, errors.New("--listen must be host:port with a port from 1 through 65534")
	}
	if host == "" {
		host = "0.0.0.0"
		listen = net.JoinHostPort(host, rawPort)
	}
	engine := aiproxy.New()
	engine.Remote = true
	engine.ListenAddress = listen
	// The PostgreSQL adapter follows the proxy port so a custom --listen keeps
	// both listeners together (9543/9544 by default).
	engine.PostgresListenAddress = net.JoinHostPort(host, strconv.Itoa(port+1))
	engine.AdvertiseHost, _ = cmd.Flags().GetString("advertise-host")
	engine.TLSCertificatePath, _ = cmd.Flags().GetString("tls-cert")
	engine.TLSPrivateKeyPath, _ = cmd.Flags().GetString("tls-key")
	engine.Lockdown, _ = cmd.Flags().GetBool("lockdown")
	if rootsPath, _ := cmd.Flags().GetString("tls-ca"); strings.TrimSpace(rootsPath) != "" {
		roots, err := loadRelayRoots(strings.TrimSpace(rootsPath))
		if err != nil {
			return nil, err
		}
		engine.RemoteRootCAs = roots
	}
	engine.BootstrapSkills = relayBootstrapSkills()
	engine.Stdout = cmd.OutOrStdout()
	engine.Stderr = cmd.ErrOrStderr()
	return engine, nil
}

// loadRelayRoots reads a private root bundle for validating the relay's own
// TLS certificate chain. It only replaces chain validation on the relay; the
// sandboxes still need the same root in their trust store to reach the relay.
func loadRelayRoots(path string) (*x509.CertPool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --tls-ca: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(payload) {
		return nil, errors.New("--tls-ca contains no PEM certificates")
	}
	return roots, nil
}

// relayBootstrapSkills renders the Agent skill for every harness Phase knows,
// keyed by the path each harness reads relative to the sandbox home directory.
// Installing all of them keeps the bootstrap independent of which harness the
// sandbox runs.
func relayBootstrapSkills() []aiproxy.BootstrapSkill {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	skills := make([]aiproxy.BootstrapSkill, 0)
	for _, target := range ai.SkillTargets() {
		relative, err := filepath.Rel(home, target.Path)
		if err != nil || strings.HasPrefix(relative, "..") {
			continue
		}
		relative = filepath.ToSlash(relative)
		if seen[relative] {
			continue
		}
		seen[relative] = true
		skills = append(skills, aiproxy.BootstrapSkill{Path: relative, Content: ai.AgentSkillForHarness(target.ID)})
	}
	return skills
}

type relayRuntime interface {
	ServeManaged(context.Context, airuntime.Engine) error
}

// runRelayLoop serves backend sessions back to back on one Engine. The Engine
// keeps its proxy credential and its memory of earlier decoy generations, so a
// recycle (approval, expiry, credential update) is invisible to sandboxes apart
// from a brief listener gap. Console outages are retried with backoff; a
// rejected login stops the relay.
func runRelayLoop(parent context.Context, in io.Reader, out, errOut io.Writer, runtime relayRuntime, engine *aiproxy.Engine) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	cycles := 0
	attempt := 0
	copyListener := false
	for {
		if ctx.Err() != nil {
			return nil
		}
		cycleContext, cycleCancel := context.WithCancel(ctx)
		started := false
		engine.OnStarted = func(endpoints aiproxy.Endpoints) {
			started = true
			cycles++
			attempt = 0
			if cycles > 1 {
				_, _ = fmt.Fprintf(out, "%s Phase AI session refreshed; sandboxes keep working.\n", relayTimestamp())
				return
			}
			handoff := relayHandoffLine(endpoints)
			_, _ = io.WriteString(out, formatRelayReady(endpoints, handoff))
			if clipboardCopySupported() && !copyListener {
				copyListener = true
				_, _ = fmt.Fprintln(out, "Type c and press Enter to copy the handoff line. Press Ctrl+C to stop.")
				go listenForRelayCopy(ctx, in, out, errOut, handoff)
			} else {
				_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop.")
			}
		}
		err := runtime.ServeManaged(cycleContext, engine)
		cycleCancel()
		if ctx.Err() != nil {
			_, _ = fmt.Fprintln(out, "Phase AI relay stopped; the handoff credential is no longer valid.")
			return nil
		}
		switch {
		case errors.Is(err, airuntime.ErrSessionReprovisionRequired), errors.Is(err, airuntime.ErrSessionExpired):
			reason := "changed"
			if errors.Is(err, airuntime.ErrSessionExpired) {
				reason = "expired"
			}
			_, _ = fmt.Fprintf(out, "%s Phase AI session %s; opening a new one.\n", relayTimestamp(), reason)
			continue
		case started && err == nil:
			continue
		case relayRetryable(err, cycles > 0):
			delay := relayRetryDelayFor(attempt)
			attempt++
			_, _ = fmt.Fprintf(errOut, "%s Phase AI relay could not open a session: %v. Retrying in %s.\n", relayTimestamp(), err, delay)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				_, _ = fmt.Fprintln(out, "Phase AI relay stopped.")
				return nil
			case <-timer.C:
			}
			continue
		default:
			if err == nil {
				err = errors.New("Phase AI relay stopped unexpectedly")
			}
			return err
		}
	}
}

// relayRetryable decides whether a failed cycle is worth retrying. Before the
// first successful start only Console-side and network failures are retried;
// configuration mistakes (bind, TLS) surface immediately. Once the relay has
// served, anything but a rejected login is retried.
func relayRetryable(err error, served bool) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, airuntime.ErrAuthenticationRequired) {
		return false
	}
	var apiErr *agentapi.Error
	if errors.As(err, &apiErr) {
		return apiErr.Retryable || apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
	}
	if served {
		return true
	}
	var urlErr *url.Error
	var netErr net.Error
	return errors.As(err, &urlErr) || errors.As(err, &netErr)
}

func relayRetryDelay(attempt int) time.Duration {
	delay := time.Second
	for i := 0; i < attempt && delay < relayMaxRetryDelay; i++ {
		delay *= 2
	}
	if delay > relayMaxRetryDelay {
		delay = relayMaxRetryDelay
	}
	return delay
}

func relayTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

// relayHandoffLine is the one line a human pastes into a trusted sandbox. It
// carries the relay credential; the bootstrap it fetches installs the Phase
// CA, the environment and the Agent skills.
func relayHandoffLine(endpoints aiproxy.Endpoints) string {
	return `eval "$(curl -fsS --proxy ` + quotePOSIXShellValue(endpoints.ProxyURL.Reveal()) + ` http://phase.invalid/v1/bootstrap)"`
}

func formatRelayReady(endpoints aiproxy.Endpoints, handoff string) string {
	var out strings.Builder
	out.WriteString("🛰️  Phase AI relay ready\n")
	out.WriteString("   Proxy:       https://" + endpoints.ProxyAddress + "\n")
	if endpoints.PostgresAddress != "" {
		out.WriteString("   PostgreSQL:  " + endpoints.PostgresAddress + "\n")
	}
	if len(endpoints.Connections) == 0 {
		out.WriteString("   Connections: none yet (Agents can request them through the proxy)\n")
	} else {
		names := make([]string, 0, len(endpoints.Connections))
		for _, connection := range endpoints.Connections {
			label := strings.TrimSpace(connection.Name)
			if label == "" {
				label = connection.ConnectionID
			}
			names = append(names, label+" ("+connection.ServiceType+")")
		}
		out.WriteString("   Connections: " + strings.Join(names, ", ") + "\n")
	}
	out.WriteString("\nHand this line to a trusted sandbox. It contains the relay credential and stays valid until this process stops:\n\n")
	out.WriteString("  " + handoff + "\n\n")
	out.WriteString("The bootstrap installs the Phase CA, loads the Phase AI environment into that shell and future login shells, and installs the phase-cli-ai-relay skill.\n")
	return out.String()
}

func listenForRelayCopy(ctx context.Context, in io.Reader, out, errOut io.Writer, handoff string) {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		if strings.ToLower(strings.TrimSpace(scanner.Text())) != "c" {
			continue
		}
		if err := copyToClipboard(handoff); err != nil {
			_, _ = fmt.Fprintf(errOut, "Could not copy the handoff line: %v\n", err)
			continue
		}
		_, _ = fmt.Fprintln(out, "Handoff line copied.")
	}
}
