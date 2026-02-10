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

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "🐚 Launch a sub-shell with secrets as environment variables",
	RunE:  runShell,
}

func init() {
	shellCmd.Flags().String("env", "", "Environment name")
	shellCmd.Flags().String("app", "", "Application name")
	shellCmd.Flags().String("app-id", "", "Application ID")
	shellCmd.Flags().String("tags", "", "Filter by tags")
	shellCmd.Flags().String("path", "/", "Path filter")
	shellCmd.Flags().String("shell", "", "Shell to use (bash, zsh, fish, sh, powershell, pwsh, cmd)")
	shellCmd.Flags().String("generate-leases", "true", "Generate leases for dynamic secrets")
	shellCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	rootCmd.AddCommand(shellCmd)
}

func runShell(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	tags, _ := cmd.Flags().GetString("tags")
	path, _ := cmd.Flags().GetString("path")
	shellType, _ := cmd.Flags().GetString("shell")
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

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
		resolvedValue := sdk.ResolveAllSecrets(secret.Value, allSecrets, p, secret.Application, secret.Environment)
		resolvedSecrets[secret.Key] = resolvedValue
	}

	// Collect env/app info for display
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

	// Build environment: inherit current env, add secrets and shell markers
	envSlice := os.Environ()
	for k, v := range resolvedSecrets {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}
	envSlice = append(envSlice, "PHASE_SHELL=true")
	if len(envNames) > 0 {
		envSlice = append(envSlice, fmt.Sprintf("PHASE_ENV=%s", envNames[0]))
	}
	if len(appNames) > 0 {
		envSlice = append(envSlice, fmt.Sprintf("PHASE_APP=%s", appNames[0]))
	}
	if os.Getenv("TERM") == "" {
		envSlice = append(envSlice, "TERM=xterm-256color")
	}

	// Determine shell
	var shellArgs []string
	if shellType != "" {
		shellArgs, err = util.GetShellCommand(shellType)
		if err != nil {
			return err
		}
	} else {
		shellArgs = util.GetDefaultShell()
		if shellArgs == nil {
			return fmt.Errorf("no shell found")
		}
	}

	secretCount := len(resolvedSecrets)
	shellName := shellArgs[0]
	if path != "" && path != "/" {
		fmt.Fprintf(os.Stderr, "🐚 Initialized %s with %s secrets from Application: %s, Environment: %s, Path: %s\n",
			util.BoldGreenErr(shellName),
			util.BoldMagentaErr(fmt.Sprintf("%d", secretCount)),
			util.BoldCyanErr(strings.Join(appNames, ", ")),
			util.BoldGreenErr(strings.Join(envNames, ", ")),
			util.BoldYellowErr(path))
	} else {
		fmt.Fprintf(os.Stderr, "🐚 Initialized %s with %s secrets from Application: %s, Environment: %s\n",
			util.BoldGreenErr(shellName),
			util.BoldMagentaErr(fmt.Sprintf("%d", secretCount)),
			util.BoldCyanErr(strings.Join(appNames, ", ")),
			util.BoldGreenErr(strings.Join(envNames, ", ")))
	}
	fmt.Fprintf(os.Stderr, "%s Secrets are only available in this session. Type %s or press %s to exit.\n",
		util.BoldYellowErr("Remember:"),
		util.BoldErr("exit"),
		util.BoldErr("Ctrl+D"))

	// Launch shell
	c := exec.Command(shellArgs[0], shellArgs[1:]...)
	c.Env = envSlice
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "%s Phase secrets are no longer available.\n", util.BoldRedErr("🐚 Shell session ended."))
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "%s Phase secrets are no longer available.\n", util.BoldRedErr("🐚 Shell session ended."))
	return nil
}
