package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var aiEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "🪄  Enable the local Phase AI credential proxy",
	Long:  "Enable proxy-mediated Agent workflows. Agent processes receive binding-specific decoys and a process-local proxy capability, never live credential material or backend session credentials.",
	RunE:  runAIEnable,
}

func init() {
	aiEnableCmd.Flags().Bool("mask", false, "Mask secret values from AI (non-interactive)")
	aiEnableCmd.Flags().Bool("no-mask", false, "Allow AI to read secret values (non-interactive)")
	aiEnableCmd.Flags().String("path", "", "Install skill doc to a specific path")
	aiEnableCmd.Flags().String("harness", "", "Agent harness for automatic integration (claude-code, cursor, codex, devin, opencode, or copilot)")
	aiEnableCmd.Flags().String("mode", config.AIProxyModeLocal, "AI proxy mode")
	aiEnableCmd.Flags().String("workflow", "", "Default Agent Workflow ID (User auth)")
	aiEnableCmd.Flags().Bool("trust-ca", false, "Trust the Phase AI CA for the current user without prompting (use --trust-ca=false to decline)")
	aiCmd.AddCommand(aiEnableCmd)
}

func runAIEnable(cmd *cobra.Command, args []string) error {
	if ai.IsAIAgent() {
		return fmt.Errorf("phase ai enable must be run by the user directly, not by an AI agent")
	}
	previousAIConfig := config.LoadAIConfig()

	targetFlag, _ := cmd.Flags().GetString("path")
	maskFlag, _ := cmd.Flags().GetBool("mask")
	noMaskFlag, _ := cmd.Flags().GetBool("no-mask")
	harnessFlag, _ := cmd.Flags().GetString("harness")
	proxyMode, _ := cmd.Flags().GetString("mode")
	workflowID, _ := cmd.Flags().GetString("workflow")
	if proxyMode != config.AIProxyModeLocal {
		return fmt.Errorf("unsupported AI proxy mode %q; only local is supported", proxyMode)
	}

	// Create or load the persistent per-installation CA before offering to
	// trust its public certificate. CAStore prefers the OS keyring and uses an
	// owner-only fallback only on headless machines without keyring service.
	_, caPaths, err := (phaseproxy.CAStore{}).Ensure()
	if err != nil {
		return fmt.Errorf("prepare Phase AI CA: %w", err)
	}
	fmt.Printf("🔐 Phase AI CA ready: %s\n", caPaths.Certificate)
	if caPaths.Renewed {
		fmt.Println("   The CA was renewed. Trusting the new one below replaces the previous CA in your trust store.")
	}

	trustFlag, _ := cmd.Flags().GetBool("trust-ca")
	trustFlagChanged := cmd.Flags().Changed("trust-ca")
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	// Stock Linux installs ship without NSS certutil; macOS and Windows always
	// have their tools. Find out before offering trust, so a missing tool skips
	// the offer with an install hint instead of failing the whole enable after
	// the user accepted it.
	trustTool := phaseproxy.UserCATrustAvailability(goruntime.GOOS)
	if trustTool == nil && trustAttemptPossible(trustFlagChanged, trustFlag, interactive) {
		if notice := phaseproxy.UserCATrustNotice(goruntime.GOOS); notice != "" {
			fmt.Println("   If the CA is not trusted yet: " + notice)
		}
	}
	trustCA, prompted, err := resolveAIEnableCATrust(
		trustFlagChanged,
		trustFlag,
		interactive,
		trustTool == nil,
		promptForAIEnableCATrust,
	)
	if err != nil {
		return err
	}
	switch {
	case trustCA && trustTool != nil:
		if errors.Is(trustTool, phaseproxy.ErrUserCATrustUnsupported) {
			return fmt.Errorf("trust Phase AI CA: %w; rerun with --trust-ca=false to use process-scoped CA settings", trustTool)
		}
		return fmt.Errorf("trust Phase AI CA for current user: %s; install it and rerun, or pass --trust-ca=false", phaseproxy.UserCATrustToolHint(trustTool))
	case trustCA:
		result, err := phaseproxy.TrustCAForCurrentUser(caPaths.Certificate)
		if err != nil {
			return fmt.Errorf("trust Phase AI CA for current user: %w", err)
		}
		if result.AlreadyTrusted {
			fmt.Printf("🔐 Phase AI CA is already trusted in the %s.\n", result.Store)
		} else {
			fmt.Printf("🔐 Phase AI CA trusted in the %s.\n", result.Store)
		}
	case errors.Is(trustTool, phaseproxy.ErrUserCATrustToolMissing) && !trustFlagChanged:
		fmt.Println("   Browser CA trust skipped: " + phaseproxy.UserCATrustToolHint(trustTool) + ".")
		fmt.Println("   Command-line tools and SDKs trust the Phase AI CA through the proxy environment regardless;")
		fmt.Println("   install the package and rerun `phase ai enable --trust-ca` to cover Chrome and Chromium.")
	case prompted || trustFlagChanged:
		fmt.Println("   Phase AI CA trust unchanged. run/exec will use process-scoped CA settings.")
	default:
		fmt.Println("   Phase AI CA trust unchanged in non-interactive mode; pass --trust-ca to opt in.")
	}
	fmt.Println()

	// Step 1: Select where to install the skill doc
	var installPath string
	var selectedTarget ai.SkillTarget
	if harnessFlag == "claude" {
		harnessFlag = ai.HarnessClaudeCode
	}
	if harnessFlag != "" {
		var found bool
		selectedTarget, found = ai.SkillTargetByID(harnessFlag)
		if !found {
			return fmt.Errorf("unsupported Agent harness %q", harnessFlag)
		}
	}

	if targetFlag != "" {
		installPath = targetFlag
		if selectedTarget.ID == "" {
			selectedTarget, _ = ai.SkillTargetByPath(targetFlag)
		}
	} else if selectedTarget.ID != "" {
		installPath = selectedTarget.Path
	} else {
		targets := ai.SkillTargets()
		items := make([]string, 0, len(targets)+1)
		for _, t := range targets {
			if t.Note != "" {
				items = append(items, fmt.Sprintf("%s (%s) → %s", t.Name, t.Note, t.Path))
			} else {
				items = append(items, fmt.Sprintf("%s → %s", t.Name, t.Path))
			}
		}
		items = append(items, "Custom path...")

		targetPrompt := promptui.Select{
			Label: "🪄  Install Phase AI skill for",
			Items: items,
		}
		targetIdx, _, err := targetPrompt.Run()
		if err != nil {
			return fmt.Errorf("prompt cancelled")
		}

		if targetIdx < len(targets) {
			selectedTarget = targets[targetIdx]
			installPath = selectedTarget.Path
		} else {
			// Custom path
			pathPrompt := promptui.Prompt{
				Label: "Enter path for skill doc",
			}
			customPath, err := pathPrompt.Run()
			if err != nil {
				return fmt.Errorf("prompt cancelled")
			}
			if customPath == "" {
				return fmt.Errorf("path cannot be empty")
			}
			installPath = customPath
		}
	}
	absInstallPath, err := filepath.Abs(installPath)
	if err != nil {
		return fmt.Errorf("resolve skill install path: %w", err)
	}
	// Paths from the released layout (phase-cli/SKILL.md) and from earlier
	// development builds map onto the current Agent skill beside them; the
	// files themselves are migrated during installation.
	installPath = ai.CanonicalAgentSkillPath(absInstallPath)
	if selectedTarget.ID == "" {
		selectedTarget, _ = ai.SkillTargetByPath(installPath)
	}

	cfg := previousAIConfig
	if cfg == nil {
		cfg = &config.AIConfig{DefaultWorkflowID: workflowID}
	} else if cmd.Flags().Changed("workflow") {
		cfg.DefaultWorkflowID = workflowID
	}
	cfg.SkillInstallPath = ai.CanonicalAgentSkillPath(cfg.SkillInstallPath)
	for index, path := range cfg.SkillInstallPaths {
		cfg.SkillInstallPaths[index] = ai.CanonicalAgentSkillPath(path)
	}
	cfg.Enabled = true
	cfg.ProxyMode = proxyMode
	maskSecretValues, err := resolveAIEnableMasking(maskFlag, noMaskFlag, previousAIConfig, term.IsTerminal(int(os.Stdin.Fd())), promptForAIEnableMasking)
	if err != nil {
		return err
	}
	cfg.MaskSecretValues = maskSecretValues
	cfg.AddHarnessInstallation(selectedTarget.ID, installPath)

	// Re-enabling may change the Phase host, principal, Workflow, or CLI binary.
	// The shared runtime is stopped through its authenticated control even while
	// harness sessions hold leases: they fail open and restart the updated
	// runtime on their next prompt. Only a wrapped command in flight blocks setup.
	executable, err := claudeHookExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve Phase executable for Agent hooks: %w", err)
	}
	stopContext, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
	defer cancel()
	// Until the new config is saved, a hook must not start a daemon that would
	// read the previous one.
	releaseSetup, err := lockClaudeHookSetup(stopContext)
	if err != nil {
		return fmt.Errorf("prepare Phase AI integration update: %w", err)
	}
	defer releaseSetup()
	stoppedRuntime, err := prepareHookRuntimeForSetup(stopContext)
	if err != nil {
		return fmt.Errorf("prepare Phase AI integration update: %w", err)
	}
	fmt.Println()

	var migratedSecretsPaths []string
	for _, skillPath := range cfg.ConfiguredSkillInstallPaths() {
		harness := ""
		if filepath.Clean(skillPath) == filepath.Clean(installPath) {
			harness = selectedTarget.ID
		} else if target, found := ai.SkillTargetByPath(skillPath); found {
			harness = target.ID
		}
		result, err := ai.InstallAgentSkillForEnable(skillPath, harness)
		if err != nil {
			return fmt.Errorf("install Phase CLI skill at %s: %w", skillPath, err)
		}
		if result.MigratedSecretsPath != "" {
			migratedSecretsPaths = append(migratedSecretsPaths, result.MigratedSecretsPath)
		}
	}
	fmt.Printf("🪄 Phase skills (v%s) installed to: %s\n", ai.SkillVersion(), filepath.Dir(filepath.Dir(installPath)))
	fmt.Printf("   %s (Phase AI proxy and relay) and %s (application secrets)\n", ai.AgentSkillName, ai.SecretsSkillName)
	for _, migratedPath := range migratedSecretsPaths {
		fmt.Printf("   Earlier Phase skill migrated to: %s\n", migratedPath)
	}

	installations, skipped, err := installConfiguredAIHarnessAdapters(cmd.Context(), cfg, selectedTarget.ID, executable)
	if err != nil {
		return err
	}
	if err := config.SaveAIConfig(cfg); err != nil {
		return fmt.Errorf("failed to save AI config: %w", err)
	}
	if detail := installations[selectedTarget.ID]; detail != "" {
		fmt.Printf("🪝 %s\n", detail)
	}
	if stoppedRuntime {
		fmt.Println("   Stopped the running Phase AI proxy; open Agent sessions restart it on their next prompt.")
	}

	var principal *config.UserConfig
	if user, err := config.GetDefaultUser(); err == nil {
		principal = user
	}
	fmt.Print(formatAIEnableSummary(selectedTarget, cfg, principal, installations, skipped))
	return nil
}

// trustAttemptPossible reports whether this run may touch the trust store, so
// the dialog notice is printed only when a dialog can actually appear.
func trustAttemptPossible(flagChanged, flagValue, interactive bool) bool {
	if flagChanged {
		return flagValue
	}
	return interactive
}

// formatAIEnableSummary is the closing block of `phase ai enable`: one status
// line, then the steps the human must take before the harness can use Phase.
// It is separated from the install log by blank lines so the next steps are
// the last thing on screen.
func formatAIEnableSummary(target ai.SkillTarget, cfg *config.AIConfig, principal *config.UserConfig, installations, skipped map[string]string) string {
	var out strings.Builder
	out.WriteString("\n")
	if target.Name != "" {
		out.WriteString(util.BoldGreen("✅ Phase AI enabled for "+target.Name) + "\n")
	} else {
		out.WriteString(util.BoldGreen("✅ Phase AI enabled") + "\n")
	}
	visibility := "secret values masked"
	if cfg != nil && !cfg.MaskSecretValues {
		visibility = "AI tools can read secret values"
	}
	out.WriteString("   Local proxy · " + visibility + " · sealed values always hidden · live credentials never leave the proxy.\n")
	switch {
	case principal != nil && principal.IsAgentPrincipal():
		out.WriteString("   Workflow: scoped by your Agent-token login.\n")
	case cfg != nil && strings.TrimSpace(cfg.DefaultWorkflowID) != "":
		out.WriteString("   Default Workflow: " + strings.TrimSpace(cfg.DefaultWorkflowID) + "\n")
	default:
		out.WriteString("   No default Workflow yet: rerun `phase ai enable --workflow <id>`, or pass --workflow to phase ai run/exec.\n")
	}

	steps := aiEnableNextSteps(target.ID)
	if len(steps) > 0 {
		out.WriteString("\n")
		out.WriteString(util.Bold("👉 Before "+target.Name+" can use Phase:") + "\n")
		if len(steps) == 1 {
			out.WriteString("   " + steps[0] + "\n")
		} else {
			for index, step := range steps {
				out.WriteString(fmt.Sprintf("   %d. %s\n", index+1, step))
			}
		}
		if note := aiEnableHarnessNote(target.ID); note != "" {
			out.WriteString("   " + note + "\n")
		}
	} else if target.ID == "" {
		out.WriteString("\n   Give an Agent Phase-managed credentials with `phase ai run -- <agent>` or `phase ai exec -- <command>`.\n")
	}
	if target.ID != ai.HarnessCodex && codexHookReviewRequired(installations) {
		out.WriteString("\n")
		out.WriteString(util.BoldYellow("⚠️  Codex: its Phase hook was refreshed too.") + "\n")
		out.WriteString(fmt.Sprintf("   Open the Codex CLI, run /hooks, and trust every hook from %s@%s again.\n", ai.CodexBootstrapPluginName, ai.CodexBootstrapMarketplaceName))
	}
	if reason := skipped[ai.HarnessCodex]; reason != "" {
		out.WriteString("\n")
		out.WriteString(util.BoldYellow("⚠️  Codex: its Phase plugin is out of date and was not refreshed, because "+reason+".") + "\n")
		out.WriteString("   Rerun `phase ai enable --harness codex` with the Codex CLI on PATH to refresh it.\n")
	}
	if target.ID != "" {
		out.WriteString("\n   Add another harness with `phase ai enable --harness <name>`; existing integrations stay installed.\n")
	}
	return out.String()
}

// aiEnableNextSteps lists what the human must do before the harness picks up
// Phase. Codex additionally has to trust the hook it just received.
func aiEnableNextSteps(harness string) []string {
	switch harness {
	case ai.HarnessCodex:
		return []string{
			fmt.Sprintf("Open the Codex CLI, run /hooks, and trust every hook from %s@%s.", ai.CodexBootstrapPluginName, ai.CodexBootstrapMarketplaceName),
			aiEnableHarnessRestartMessage(ai.HarnessCodex),
		}
	case ai.HarnessClaudeCode, ai.HarnessCursor, ai.HarnessOpenCode, ai.HarnessDevin:
		return []string{aiEnableHarnessRestartMessage(harness)}
	case ai.HarnessCopilot:
		return []string{"Start a new Copilot chat so it loads the skill."}
	default:
		return nil
	}
}

// aiEnableHarnessNote says how Phase shows up in that harness afterwards.
func aiEnableHarnessNote(harness string) string {
	switch harness {
	case ai.HarnessClaudeCode, ai.HarnessOpenCode:
		return "Shell commands then use Phase-managed credentials automatically while the proxy runs; `phase ai status` shows it."
	case ai.HarnessCodex:
		return "It can then discover and run explicitly chosen Phase-managed Connections; ordinary shell commands stay ambient. " +
			"Each Phase call needs Codex's network approval in the default sandbox; set `network_access = true` under `[sandbox_workspace_write]` in ~/.codex/config.toml to skip that."
	case ai.HarnessCursor, ai.HarnessDevin:
		return "It can then discover and run explicitly chosen Phase-managed Connections; ordinary shell commands stay ambient."
	case ai.HarnessCopilot:
		return "Copilot uses the skill only: run Phase-managed commands with `phase ai exec -- <command>`."
	default:
		return ""
	}
}

func aiEnableHarnessRestartMessage(harness string) string {
	switch harness {
	case ai.HarnessClaudeCode:
		return "Fully quit and restart Claude Code or Claude Desktop, start a new chat, then repeat the original prompt."
	case ai.HarnessCursor:
		return "Reload or fully restart Cursor, start a new Agent chat, then repeat the original prompt."
	case ai.HarnessCodex:
		return "Fully quit and restart Codex Desktop or the Codex CLI, start a new task, then repeat the original prompt."
	case ai.HarnessOpenCode:
		return "Fully quit and restart OpenCode, start a new session, then repeat the original prompt."
	case ai.HarnessDevin:
		return "Fully quit and restart local Devin, start a new session, verify /hooks, then repeat the original prompt."
	default:
		return ""
	}
}

func claudeHookExecutablePath() (string, error) {
	if resolved, err := exec.LookPath(os.Args[0]); err == nil {
		if absolute, absErr := filepath.Abs(resolved); absErr == nil {
			return absolute, nil
		}
	}
	return os.Executable()
}

// installConfiguredAIHarnessAdapters refreshes one major-versioned helper from
// the current CLI, then points every thin harness adapter at it. Provider and
// discovery changes do not require reinstalling those adapters. When another
// harness is selected, a current Codex adapter is left alone, and an outdated
// one is returned as skipped when the Codex CLI is not on PATH. Where the
// OpenCode plugin is installed is recorded in cfg.
func installConfiguredAIHarnessAdapters(ctx context.Context, cfg *config.AIConfig, selected, executable string) (map[string]string, map[string]string, error) {
	harnesses := cfg.ConfiguredHarnessIDs()
	installed := make(map[string]string, len(harnesses))
	skipped := make(map[string]string)
	hookExecutable := executable
	for _, harness := range harnesses {
		if harness == ai.HarnessCopilot {
			continue
		}
		shared, err := ai.InstallSharedHookExecutable(executable)
		if err != nil {
			return nil, nil, fmt.Errorf("install shared Phase Agent hook: %w", err)
		}
		hookExecutable = shared.ExecutablePath
		break
	}
	for _, harness := range harnesses {
		switch harness {
		case ai.HarnessClaudeCode:
			path, err := ai.DefaultClaudeBootstrapPluginPath()
			if err != nil {
				return nil, nil, err
			}
			if err := ai.InstallClaudeBootstrapPlugin(path, hookExecutable); err != nil {
				return nil, nil, fmt.Errorf("install Claude Phase discovery adapter: %w", err)
			}
			installed[harness] = "Claude Phase discovery adapter installed to: " + path
		case ai.HarnessCursor:
			path, err := ai.DefaultCursorBootstrapPluginPath()
			if err != nil {
				return nil, nil, err
			}
			if err := ai.InstallCursorBootstrapPlugin(path, hookExecutable); err != nil {
				return nil, nil, fmt.Errorf("install Cursor Phase discovery adapter: %w", err)
			}
			installed[harness] = "Cursor Phase discovery adapter installed to: " + path
		case ai.HarnessCodex:
			path, err := ai.DefaultCodexBootstrapMarketplacePath()
			if err != nil {
				return nil, nil, err
			}
			if harness != selected && ai.CodexBootstrapPluginCurrent(path, hookExecutable) {
				continue
			}
			codexExecutable, err := exec.LookPath("codex")
			if err != nil && harness != selected {
				skipped[harness] = "the Codex CLI is not on PATH"
				continue
			}
			if err != nil {
				return nil, nil, errors.New("Codex CLI is required to install the Phase plugin; install Codex or add its CLI to PATH, then rerun `phase ai enable --harness codex`")
			}
			installation, err := ai.InstallCodexBootstrapPlugin(path, hookExecutable)
			if err != nil {
				return nil, nil, fmt.Errorf("install Codex Phase discovery adapter: %w", err)
			}
			if err := ai.ActivateCodexBootstrapPlugin(ctx, codexExecutable, path); err != nil {
				return nil, nil, fmt.Errorf("activate Codex Phase discovery adapter: %w", err)
			}
			installed[harness] = "Codex Phase discovery adapter installed: " + installation.Selector
		case ai.HarnessOpenCode:
			runtimeDirectory, err := claudeHookRuntimeDir()
			if err != nil {
				return nil, nil, err
			}
			paths := cfg.OpenCodePlugins
			if len(paths) == 0 {
				if paths, err = ai.FindOpenCodePlugins(cfg.ConfiguredSkillInstallPaths()); err != nil {
					return nil, nil, err
				}
			}
			// Enabling another harness may run without OpenCode's environment, so
			// only OpenCode's own enable adds the current environment's root.
			if harness == selected {
				path, err := ai.DefaultOpenCodePluginPath()
				if err != nil {
					return nil, nil, err
				}
				if !slices.Contains(paths, path) {
					paths = append(paths, path)
				}
			}
			for _, path := range paths {
				// A foreign file must not be recorded, or disable would try to remove it.
				if err := ai.ClaimOpenCodePlugin(path); err != nil {
					return nil, nil, fmt.Errorf("install OpenCode Phase plugin at %s: %w", path, err)
				}
				if err := config.RecordOpenCodePlugin(path); err != nil {
					return nil, nil, fmt.Errorf("record OpenCode Phase plugin: %w", err)
				}
				if _, err := ai.InstallOpenCodePlugin(path, hookExecutable, claudeEnvironmentJSONPath(runtimeDirectory)); err != nil {
					return nil, nil, fmt.Errorf("install OpenCode Phase plugin at %s: %w", path, err)
				}
			}
			cfg.OpenCodePlugins = paths
			installed[harness] = "OpenCode Phase plugin installed to: " + strings.Join(paths, ", ")
		case ai.HarnessDevin:
			path, err := ai.DefaultDevinConfigPath()
			if err != nil {
				return nil, nil, err
			}
			installation, err := ai.InstallDevinHooks(path, hookExecutable)
			if err != nil {
				return nil, nil, fmt.Errorf("install Devin Phase discovery adapter: %w", err)
			}
			installed[harness] = "Devin Phase discovery adapter installed in: " + installation.ConfigPath
		case ai.HarnessCopilot:
			// Copilot consumes only the Agent Skill; it has no automatic helper.
		default:
			return nil, nil, fmt.Errorf("unsupported configured Agent harness %q", harness)
		}
	}
	return installed, skipped, nil
}

func codexHookReviewRequired(installations map[string]string) bool {
	return installations[ai.HarnessCodex] != ""
}

// resolveAIEnableCATrust decides whether to edit the user's trust store. An
// explicit flag always wins; otherwise the user is asked only when the
// session is interactive and the platform's trust tool is installed.
func resolveAIEnableCATrust(flagChanged, flagValue, interactive, toolAvailable bool, prompt func() (bool, error)) (trust, prompted bool, err error) {
	if flagChanged {
		return flagValue, false, nil
	}
	if !interactive || !toolAvailable {
		return false, false, nil
	}
	trust, err = prompt()
	return trust, true, err
}

func promptForAIEnableCATrust() (bool, error) {
	prompt := promptui.Prompt{
		Label:     "Trust the Phase AI CA for this user",
		IsConfirm: true,
		Default:   "y",
	}
	_, err := prompt.Run()
	if errors.Is(err, promptui.ErrAbort) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("CA trust prompt cancelled")
	}
	return true, nil
}

// resolveAIEnableMasking keeps the released secret-visibility choice: explicit
// flags win, an interactive run asks, and a non-interactive run keeps the
// previous preference or masks by default.
func resolveAIEnableMasking(maskFlag, noMaskFlag bool, previous *config.AIConfig, interactive bool, prompt func() (bool, error)) (bool, error) {
	switch {
	case maskFlag && noMaskFlag:
		return false, fmt.Errorf("cannot use both --mask and --no-mask")
	case maskFlag:
		return true, nil
	case noMaskFlag:
		return false, nil
	case !interactive:
		if previous != nil {
			return previous.MaskSecretValues, nil
		}
		return true, nil
	}
	return prompt()
}

func promptForAIEnableMasking() (bool, error) {
	fmt.Println()
	fmt.Println("   Secret visibility for AI agents:")
	fmt.Println("   ┌─────────────┬────────────────────┬──────────────────────────┐")
	fmt.Println("   │ Secret type │ Example            │ AI Visibility            │")
	fmt.Println("   ├─────────────┼────────────────────┼──────────────────────────┤")
	fmt.Println("   │ config      │ REDIS_PORT=6379    │ always visible           │")
	fmt.Println(util.BoldMagenta("   │ secret      │ REDIS_HOST=?.?.?.? │ 👈 mask secret value?    │"))
	fmt.Println("   │ sealed      │ REDIS_PASSWORD=███ │ never visible!           │")
	fmt.Println("   └─────────────┴────────────────────┴──────────────────────────┘")
	fmt.Println()

	maskPrompt := promptui.Select{
		Label: "🔒 Mask secret values from AI agents?",
		Items: []string{
			"Yes — mask secret values",
			"No — allow AI to read secret values (e.g. development environments)",
		},
	}
	maskIdx, _, err := maskPrompt.Run()
	if err != nil {
		return false, fmt.Errorf("prompt cancelled")
	}
	return maskIdx == 0, nil
}
