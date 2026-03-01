package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:                "run <command>",
	Short:              "🚀 Run and inject secrets to your app",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: false,
	RunE:               runRun,
}

func init() {
	runCmd.Flags().String("env", "", "Environment name")
	runCmd.Flags().String("app", "", "Application name")
	runCmd.Flags().String("app-id", "", "Application ID")
	runCmd.Flags().String("tags", "", "Filter by tags")
	runCmd.Flags().String("path", "/", "Path filter")
	runCmd.Flags().String("generate-leases", "true", "Generate leases for dynamic secrets")
	runCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	tags, _ := cmd.Flags().GetString("tags")
	path, _ := cmd.Flags().GetString("path")
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	// Fetch secrets
	opts := sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Tag:     tags,
		Path:    path,
		Dynamic: true,
		Lease:   util.ParseBoolFlag(generateLeases),
	}
	if cmd.Flags().Changed("lease-ttl") {
		opts.LeaseTTL = &leaseTTL
	}

	spinner := util.NewSpinner("Fetching secrets...")
	spinner.Start()
	allSecrets, err := p.Get(opts)
	spinner.Stop()
	if err != nil {
		return err
	}

	// Resolve references
	resolvedSecrets := map[string]string{}
	for _, secret := range allSecrets {
		if secret.Value == "" {
			continue
		}
		resolvedValue, err := sdk.ResolveAllSecrets(secret.Value, allSecrets, p, secret.Application, secret.Environment)
		if err != nil {
			return err
		}
		resolvedSecrets[secret.Key] = resolvedValue
	}

	// Print injection stats to stderr (matches Python CLI behavior)
	secretCount := len(resolvedSecrets)
	apps := map[string]bool{}
	envs := map[string]bool{}
	for _, s := range allSecrets {
		if _, ok := resolvedSecrets[s.Key]; ok {
			if s.Application != "" {
				apps[s.Application] = true
			}
			envs[s.Environment] = true
		}
	}
	appNames := mapKeys(apps)
	envNames := mapKeys(envs)

	if path != "" && path != "/" {
		fmt.Fprintf(os.Stderr, "🚀 Injected %s secrets from Application: %s, Environment: %s, Path: %s\n",
			util.BoldMagentaErr(fmt.Sprintf("%d", secretCount)),
			util.BoldCyanErr(strings.Join(appNames, ", ")),
			util.BoldGreenErr(strings.Join(envNames, ", ")),
			util.BoldYellowErr(path))
	} else {
		fmt.Fprintf(os.Stderr, "🚀 Injected %s secrets from Application: %s, Environment: %s\n",
			util.BoldMagentaErr(fmt.Sprintf("%d", secretCount)),
			util.BoldCyanErr(strings.Join(appNames, ", ")),
			util.BoldGreenErr(strings.Join(envNames, ", ")))
	}

	// Build environment: inherit current env and append secrets
	envSlice := os.Environ()
	for k, v := range resolvedSecrets {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	// Execute command
	command := strings.Join(args, " ")
	shell := util.GetDefaultShell()
	var c *exec.Cmd
	if len(shell) > 0 {
		c = exec.Command(shell[0], "-c", command)
	} else {
		c = exec.Command("sh", "-c", command)
	}
	c.Env = envSlice
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin

	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
