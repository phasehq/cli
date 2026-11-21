package cmd

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel/engine"
	"github.com/phasehq/cli/internal/tunnel/helper"
	"github.com/phasehq/cli/pkg/version"
	"github.com/spf13/cobra"
)

// The parts of `phase up`. They're commands so the helper and the engine are the same
// program as the CLI, but nobody needs to run them by hand.
var tunnelCmd = &cobra.Command{
	Use:    "tunnel",
	Short:  "The parts of phase up",
	Hidden: true,
}

var tunnelHelperCmd = &cobra.Command{
	Use:   "helper",
	Short: "The privileged helper, started by the system",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Geteuid() != 0 {
			return errors.New("the helper runs as root, started by the system; phase up installs it")
		}
		uid, _ := cmd.Flags().GetInt("uid")
		if uid <= 0 {
			return errors.New("the helper needs --uid, the user it serves")
		}
		logger := log.New(os.Stderr, "", log.LstdFlags)
		instance, err := helper.New(helper.Options{SocketPath: helper.SocketPath, AllowedUID: uid, Version: version.Version, Logf: logger.Printf})
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return instance.Run(ctx)
	},
}

var tunnelEngineCmd = &cobra.Command{
	Use:   "engine",
	Short: "The engine, started by phase up",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Geteuid() == 0 {
			return errors.New("the engine holds credentials, so it must not run as root")
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
		directory, err := tunnelStateDirectory()
		if err != nil {
			return err
		}
		logger := log.New(os.Stderr, "", log.LstdFlags)
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		// The proxy's leak protection says which model hosts are read, each for its own
		// tool's processes only. Every other program's traffic to them passes unread.
		return engine.Run(ctx, engine.Config{
			Runtime: runtimeInstance, SocketPath: tunnelHelperSocket, StateDirectory: directory, Logf: logger.Printf,
			Routes: routes, Reader: engine.ProxyReader, OtherProxy: otherProxySet(os.Environ()),
		})
	},
}

var tunnelInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the helper, as root",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		uid, _ := cmd.Flags().GetInt("uid")
		return helper.Install(uid)
	},
}

var tunnelUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the helper, as root",
	Args:  cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		return helper.Uninstall()
	},
}

// tunnelStateDirectory is where the engine keeps its state, and tunnelHelperSocket is
// where the helper listens. They're variables so a test can never reach the real ones.
var (
	tunnelStateDirectory = func() (string, error) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".phase", "tunnel"), nil
	}
	tunnelHelperSocket = helper.SocketPath
)

func init() {
	tunnelHelperCmd.Flags().Int("uid", 0, "the user the helper serves")
	tunnelEngineCmd.Flags().String("workflow", "", "Agent Workflow, for a user login")
	tunnelEngineCmd.Flags().String("routes", "", "networks to capture in place of everything")
	tunnelInstallCmd.Flags().Int("uid", 0, "the user the helper serves")
	tunnelCmd.AddCommand(tunnelHelperCmd, tunnelEngineCmd, tunnelInstallCmd, tunnelUninstallCmd)
	rootCmd.AddCommand(tunnelCmd)
}
