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
	aiEnableCmd.Flags().String("path", "", "Install skill doc to a specific path")
	aiEnableCmd.Flags().String("harness", "", "Agent harness for automatic integration (claude-code, cursor, codex, opencode, or copilot)")
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
	harnessFlag, _ := cmd.Flags().GetString("harness")
	workflowID, _ := cmd.Flags().GetString("workflow")

	if aiCAStore.KeystoreAvailable() {
		if err := prepareAIEnableCA(cmd); err != nil {
			return err
		}
	} else {
		// Without a keystore the CA key lives only in each proxy process, so
		// there is no lasting CA to create here or to trust.
		fmt.Println("🔐 " + phaseproxy.NoKeystoreNotice)
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
	// A path in a skill directory from an earlier build installs the current
	// skill beside it.
	installPath = ai.CanonicalSkillPath(absInstallPath)
	if selectedTarget.ID == "" {
		selectedTarget, _ = ai.SkillTargetByPath(installPath)
	}

	cfg := previousAIConfig
	if cfg == nil {
		cfg = &config.AIConfig{DefaultWorkflowID: workflowID}
	} else if cmd.Flags().Changed("workflow") {
		cfg.DefaultWorkflowID = workflowID
	}
	for index, path := range cfg.SkillInstallPaths {
		cfg.SkillInstallPaths[index] = ai.CanonicalSkillPath(path)
	}
	cfg.Enabled = true
	cfg.AddHarnessInstallation(selectedTarget.ID, installPath)

	// Re-enabling may change the Phase host, principal, Workflow, or CLI binary.
	// The shared runtime is stopped through its authenticated control even while
	// harness sessions hold leases: they fail open and restart the updated
	// runtime on their next prompt. Only a wrapped command in flight blocks setup.
	executable, err := hookExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve Phase executable for Agent hooks: %w", err)
	}
	stopContext, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
	defer cancel()
	// Until the new config is saved, a hook must not start a daemon that would
	// read the previous one.
	releaseSetup, err := lockHookSetup(stopContext)
	if err != nil {
		return fmt.Errorf("prepare Phase AI integration update: %w", err)
	}
	defer releaseSetup()
	stoppedRuntime, err := prepareHookRuntimeForSetup(stopContext)
	if err != nil {
		return fmt.Errorf("prepare Phase AI integration update: %w", err)
	}
	fmt.Println()

	var keptModified, removedFormer []string
	for _, skillPath := range cfg.ConfiguredSkillInstallPaths() {
		harness := ""
		if filepath.Clean(skillPath) == filepath.Clean(installPath) {
			harness = selectedTarget.ID
		} else if target, found := ai.SkillTargetByPath(skillPath); found {
			harness = target.ID
		}
		result, err := ai.InstallSkill(skillPath, harness)
		if err != nil {
			return fmt.Errorf("install Phase CLI skill at %s: %w", skillPath, err)
		}
		if result.KeptModified {
			keptModified = append(keptModified, result.Path)
		}
		removedFormer = append(removedFormer, result.RemovedFormer...)
	}
	fmt.Printf("🪄 Phase skill %s (v%s) installed to: %s\n", ai.SkillName, ai.SkillVersion(), filepath.Dir(filepath.Dir(installPath)))
	for _, path := range keptModified {
		fmt.Printf("   Kept your edited skill at %s; delete it and rerun `phase ai enable` to install the current one.\n", path)
	}
	for _, path := range removedFormer {
		fmt.Printf("   Removed a skill from an earlier Phase build: %s\n", path)
	}

	installations, skipped, err := installConfiguredAIHarnessAdapters(cmd.Context(), cfg, selectedTarget.ID, executable)
	if err != nil {
		return err
	}
	if err := config.SaveAIConfig(cfg); err != nil {
		return fmt.Errorf("failed to save AI config: %w", err)
	}
	sweepAIDirectoryQuietly(cmd.Context())
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

// aiCAStore is the per-installation CA store; tests replace its keystore.
var aiCAStore = phaseproxy.CAStore{}

// prepareAIEnableCA creates or loads the per-installation CA, whose key is in
// the system keystore, and offers to trust its public certificate.
func prepareAIEnableCA(cmd *cobra.Command) error {
	_, caPaths, err := aiCAStore.Ensure()
	if err != nil {
		return fmt.Errorf("prepare Phase AI CA: %w", err)
	}
	if caPaths.MemoryOnly {
		// The keystore answered the probe but would not store the key.
		fmt.Println("🔐 " + phaseproxy.NoKeystoreNotice)
		return nil
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

// aiEnableTryPrompt is what the final step asks the human to say, so the
// harness exercises Phase end to end on its first prompt.
const aiEnableTryPrompt = "Set up an AWS connection using Phase and run get caller identity"

// formatAIEnableSummary is the closing block of `phase ai enable`: one status
// line, any step the human must take before the harness can use Phase, then
// the final step. It is separated from the install log by blank lines so the
// final step is the last thing on screen.
func formatAIEnableSummary(target ai.SkillTarget, cfg *config.AIConfig, principal *config.UserConfig, installations, skipped map[string]string) string {
	var out strings.Builder
	out.WriteString("\n")
	if target.Name != "" {
		out.WriteString(util.BoldGreen("✅ Phase AI enabled for "+target.Name) + "\n")
	} else {
		out.WriteString(util.BoldGreen("✅ Phase AI enabled") + "\n")
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

	steps := aiEnableRequiredSteps(target.ID, cfg, principal)
	if len(steps) > 0 {
		out.WriteString("\n")
		if target.Name != "" {
			out.WriteString(util.Bold("Before "+target.Name+" can use Phase:") + "\n")
		} else {
			out.WriteString(util.Bold("Before an Agent can use Phase:") + "\n")
		}
		for index, step := range steps {
			out.WriteString(fmt.Sprintf("   %d. %s\n", index+1, step))
		}
	}
	out.WriteString("\n")
	if target.ID == "" {
		out.WriteString(util.Bold("👉 Final step: give an Agent Phase-managed credentials with `phase ai run -- <agent>` or `phase ai exec -- <command>`.") + "\n")
		return out.String()
	}
	open, restart := aiEnableHarnessLaunch(target)
	out.WriteString(util.Bold("👉 Final step: "+open+" and say:") + "\n")
	out.WriteString("   \"" + aiEnableTryPrompt + "\"\n")
	out.WriteString("   " + restart + "\n")
	return out.String()
}

// aiEnableRequiredSteps lists what must happen before the harness can use
// Phase: Codex runs a hook only after the human trusts it, and a User login
// needs a default Workflow for the automatic proxy.
func aiEnableRequiredSteps(harness string, cfg *config.AIConfig, principal *config.UserConfig) []string {
	steps := make([]string, 0, 2)
	agentLogin := principal != nil && principal.IsAgentPrincipal()
	if !agentLogin && (cfg == nil || strings.TrimSpace(cfg.DefaultWorkflowID) == "") {
		steps = append(steps, "Set a default Workflow with `phase ai enable --workflow <id>`.")
	}
	if harness == ai.HarnessCodex {
		steps = append(steps, fmt.Sprintf("Open the Codex CLI, run /hooks, and trust every hook from %s@%s.", ai.CodexBootstrapPluginName, ai.CodexBootstrapMarketplaceName))
	}
	return steps
}

// aiEnableHarnessLaunch says where the human starts the harness and what to do
// if an already running instance has not loaded the new integration.
func aiEnableHarnessLaunch(target ai.SkillTarget) (open, restart string) {
	switch target.ID {
	case ai.HarnessClaudeCode:
		return "open Claude Code (desktop or CLI)", "Restart Claude Code only if it does not pick up Phase."
	case ai.HarnessCursor:
		return "open a new Agent chat in Cursor", "Reload the Cursor window only if it does not pick up Phase."
	case ai.HarnessCodex:
		return "start a new task in Codex (desktop or CLI)", "Restart Codex only if it does not pick up Phase."
	case ai.HarnessOpenCode:
		return "start a new OpenCode session", "Restart OpenCode only if it does not pick up Phase."
	case ai.HarnessCopilot:
		return "start a new Copilot chat in VS Code", "Reload VS Code only if Copilot does not pick up the Phase skill."
	default:
		return "open " + target.Name, "Restart " + target.Name + " only if it does not pick up Phase."
	}
}

func hookExecutablePath() (string, error) {
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
			runtimeDirectory, err := hookRuntimeDir()
			if err != nil {
				return nil, nil, err
			}
			paths := slices.Clone(cfg.OpenCodePlugins)
			// Enabling another harness may run without OpenCode's environment, so
			// only OpenCode's own enable adds the current environment's root.
			if harness == selected || len(paths) == 0 {
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
				if _, err := ai.InstallOpenCodePlugin(path, hookExecutable, runtimeEnvironmentJSONPath(runtimeDirectory)); err != nil {
					return nil, nil, fmt.Errorf("install OpenCode Phase plugin at %s: %w", path, err)
				}
			}
			cfg.OpenCodePlugins = paths
			installed[harness] = "OpenCode Phase plugin installed to: " + strings.Join(paths, ", ")
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
