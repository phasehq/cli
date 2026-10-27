package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	CodexBootstrapPluginName      = "phase-ai-bootstrap"
	CodexBootstrapMarketplaceName = "phase-cli-local"

	codexBootstrapMarkerName = ".phase-owned.json"
)

// CodexBootstrapInstall describes the Phase-owned local marketplace and plugin
// source produced by InstallCodexBootstrapPlugin.
type CodexBootstrapInstall struct {
	MarketplaceRoot string
	PluginRoot      string
	PluginVersion   string
	Selector        string
}

type codexPluginManifest struct {
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	Description string               `json:"description"`
	Author      codexPluginAuthor    `json:"author"`
	Homepage    string               `json:"homepage,omitempty"`
	Repository  string               `json:"repository,omitempty"`
	License     string               `json:"license,omitempty"`
	Keywords    []string             `json:"keywords,omitempty"`
	Interface   codexPluginInterface `json:"interface"`
}

type codexPluginAuthor struct {
	Name string `json:"name"`
}

type codexPluginInterface struct {
	DisplayName      string   `json:"displayName"`
	ShortDescription string   `json:"shortDescription"`
	LongDescription  string   `json:"longDescription"`
	DeveloperName    string   `json:"developerName"`
	Category         string   `json:"category"`
	Capabilities     []string `json:"capabilities"`
	DefaultPrompt    []string `json:"defaultPrompt"`
}

type codexHookFile struct {
	Description string                        `json:"description,omitempty"`
	Hooks       map[string][]codexHookMatcher `json:"hooks"`
}

type codexHookMatcher struct {
	Matcher string             `json:"matcher,omitempty"`
	Hooks   []codexHookHandler `json:"hooks"`
}

type codexHookHandler struct {
	Type                   string `json:"type"`
	Command                string `json:"command"`
	CommandWindows         string `json:"commandWindows,omitempty"`
	Timeout                int    `json:"timeout"`
	StatusMessage          string `json:"statusMessage,omitempty"`
	AdditionalContextLimit int    `json:"additionalContextLimit,omitempty"`
}

type codexMarketplaceMarker struct {
	Owner           string `json:"owner"`
	Marketplace     string `json:"marketplace"`
	Plugin          string `json:"plugin"`
	AdapterProtocol string `json:"adapterProtocol,omitempty"`
}

type codexMarketplaceEntry struct {
	Name     string                 `json:"name"`
	Source   codexMarketplaceSource `json:"source"`
	Policy   codexMarketplacePolicy `json:"policy"`
	Category string                 `json:"category"`
}

type codexMarketplaceSource struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

type codexMarketplacePolicy struct {
	Installation   string `json:"installation"`
	Authentication string `json:"authentication"`
}

type codexMarketplaceList struct {
	Marketplaces []codexMarketplaceInfo `json:"marketplaces"`
}

type codexMarketplaceInfo struct {
	Name              string                     `json:"name"`
	Root              string                     `json:"root"`
	MarketplaceSource codexConfiguredMarketplace `json:"marketplaceSource"`
}

type codexConfiguredMarketplace struct {
	SourceType string `json:"sourceType"`
	Source     string `json:"source"`
}

type codexPluginList struct {
	Installed []codexInstalledPlugin `json:"installed"`
}

type codexInstalledPlugin struct {
	PluginID        string `json:"pluginId"`
	Name            string `json:"name"`
	MarketplaceName string `json:"marketplaceName"`
	Installed       bool   `json:"installed"`
}

type codexCommandRunner func(context.Context, string, ...string) ([]byte, error)

// DefaultCodexBootstrapMarketplacePath returns the Phase-owned local Codex
// marketplace. It intentionally does not modify the user's personal
// marketplace or ~/.codex/hooks.json.
func DefaultCodexBootstrapMarketplacePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".phase", "ai", "codex-marketplace"), nil
}

// InstallCodexBootstrapPlugin creates or refreshes the Phase-owned local
// marketplace source. The shared helper gives Codex Desktop a stable launcher
// even when its PATH differs from the user's shell. This function
// only writes the source bundle; ActivateCodexBootstrapPlugin performs the
// official Codex marketplace and plugin registration.
func InstallCodexBootstrapPlugin(root, phaseExecutable string) (CodexBootstrapInstall, error) {
	installation := CodexBootstrapInstall{
		MarketplaceRoot: root,
		PluginRoot:      filepath.Join(root, "plugins", CodexBootstrapPluginName),
		Selector:        codexPluginSelector(),
	}
	if root == "" {
		return installation, errors.New("Codex bootstrap marketplace path is required")
	}
	if !filepath.IsAbs(phaseExecutable) {
		return installation, errors.New("Phase executable path for the Codex hook must be absolute")
	}
	if err := claimCodexMarketplace(root); err != nil {
		return installation, err
	}

	manifestDirectory := filepath.Join(installation.PluginRoot, ".codex-plugin")
	hooksDirectory := filepath.Join(installation.PluginRoot, "hooks")
	for _, directory := range []string{manifestDirectory, hooksDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return installation, fmt.Errorf("create Codex bootstrap plugin directory %s: %w", directory, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(codexMarketplaceManifestPath(root)), 0o700); err != nil {
		return installation, fmt.Errorf("create Codex marketplace manifest directory: %w", err)
	}

	hookExecutable := phaseExecutable
	installation.PluginVersion = HarnessAdapterProtocolVersion

	hooks := codexBootstrapHooks(hookExecutable)
	manifest := codexBootstrapManifest()
	if err := writeJSONFile(filepath.Join(manifestDirectory, "plugin.json"), manifest, 0o600); err != nil {
		return installation, fmt.Errorf("write Codex bootstrap plugin manifest: %w", err)
	}
	if err := writeJSONFile(filepath.Join(hooksDirectory, "hooks.json"), hooks, 0o600); err != nil {
		return installation, fmt.Errorf("write Codex bootstrap hooks: %w", err)
	}
	if err := upsertCodexMarketplace(root); err != nil {
		return installation, err
	}
	return installation, nil
}

// codexBootstrapManifest is the plugin.json InstallCodexBootstrapPlugin writes.
func codexBootstrapManifest() codexPluginManifest {
	return codexPluginManifest{
		Name:        CodexBootstrapPluginName,
		Version:     HarnessAdapterProtocolVersion,
		Description: "Makes explicitly selected Phase-managed Connections available to Codex.",
		Author:      codexPluginAuthor{Name: "Phase"},
		Homepage:    "https://phase.dev",
		Repository:  "https://github.com/phasehq/cli",
		License:     "GPL-3.0",
		Keywords:    []string{"phase", "credentials", "agents", "proxy"},
		Interface: codexPluginInterface{
			DisplayName:      "Phase AI",
			ShortDescription: "Use credentials through a local Phase proxy",
			LongDescription:  "Discovers and executes explicitly selected Phase-managed Connections while ordinary tools remain ambient.",
			DeveloperName:    "Phase",
			Category:         "Engineering",
			Capabilities:     []string{"Interactive"},
			DefaultPrompt: []string{
				"Use a Phase-managed Connection",
				"Set up a third-party Connection",
			},
		},
	}
}

// CodexBootstrapPluginCurrent reports whether the plugin under root already
// holds exactly the manifest and hooks InstallCodexBootstrapPlugin would write
// for phaseExecutable, so refreshing it would change nothing Codex runs. It
// needs no Codex CLI.
func CodexBootstrapPluginCurrent(root, phaseExecutable string) bool {
	pluginRoot := filepath.Join(root, "plugins", CodexBootstrapPluginName)
	for path, value := range map[string]any{
		filepath.Join(pluginRoot, ".codex-plugin", "plugin.json"): codexBootstrapManifest(),
		filepath.Join(pluginRoot, "hooks", "hooks.json"):          codexBootstrapHooks(phaseExecutable),
	} {
		want, err := jsonFilePayload(value)
		if err != nil {
			return false
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			return false
		}
	}
	return true
}

// ActivateCodexBootstrapPlugin registers the Phase-owned marketplace and
// installs (or refreshes) the plugin via Codex's supported CLI. Hook trust is
// deliberately left to Codex's /hooks review flow.
func ActivateCodexBootstrapPlugin(ctx context.Context, codexExecutable, root string) error {
	return activateCodexBootstrapPlugin(ctx, codexExecutable, root, runCodexCommand)
}

func activateCodexBootstrapPlugin(ctx context.Context, codexExecutable, root string, runner codexCommandRunner) error {
	if codexExecutable == "" {
		return errors.New("Codex executable path is required")
	}
	if err := validateCodexMarketplaceOwnership(root); err != nil {
		return err
	}
	marketplaces, err := listCodexMarketplaces(ctx, codexExecutable, runner)
	if err != nil {
		return err
	}
	found := false
	for _, marketplace := range marketplaces {
		if marketplace.Name != CodexBootstrapMarketplaceName {
			continue
		}
		found = true
		configuredRoot := marketplace.Root
		if configuredRoot == "" && marketplace.MarketplaceSource.SourceType == "local" {
			configuredRoot = marketplace.MarketplaceSource.Source
		}
		if !sameLocalPath(configuredRoot, root) {
			return fmt.Errorf("Codex marketplace %q already points to %s, not the Phase-owned path %s", CodexBootstrapMarketplaceName, configuredRoot, root)
		}
	}
	if !found {
		if _, err := runner(ctx, codexExecutable, "plugin", "marketplace", "add", root, "--json"); err != nil {
			return fmt.Errorf("register Phase Codex marketplace: %w", err)
		}
	}
	if _, err := runner(ctx, codexExecutable, "plugin", "add", codexPluginSelector(), "--json"); err != nil {
		return fmt.Errorf("install Phase Codex plugin: %w", err)
	}
	return nil
}

// UninstallCodexBootstrapPlugin removes only the Phase plugin, its official
// Codex registrations, and Phase-owned marketplace files. Unrelated entries or
// files under the marketplace root are preserved.
func UninstallCodexBootstrapPlugin(ctx context.Context, codexExecutable, root string) error {
	return uninstallCodexBootstrapPlugin(ctx, codexExecutable, root, runCodexCommand)
}

func uninstallCodexBootstrapPlugin(ctx context.Context, codexExecutable, root string, runner codexCommandRunner) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Codex bootstrap marketplace: %w", err)
	}
	if codexExecutable == "" {
		return errors.New("Codex executable path is required")
	}
	present, err := codexBootstrapPresent(root)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := validateCodexMarketplaceOwnership(root); err != nil {
		return err
	}

	marketplaces, err := listCodexMarketplaces(ctx, codexExecutable, runner)
	if err != nil {
		return err
	}
	marketplaceConfigured := false
	for _, marketplace := range marketplaces {
		if marketplace.Name != CodexBootstrapMarketplaceName {
			continue
		}
		configuredRoot := marketplace.Root
		if configuredRoot == "" && marketplace.MarketplaceSource.SourceType == "local" {
			configuredRoot = marketplace.MarketplaceSource.Source
		}
		if !sameLocalPath(configuredRoot, root) {
			return fmt.Errorf("refusing to remove Codex marketplace %q because it points to %s", CodexBootstrapMarketplaceName, configuredRoot)
		}
		marketplaceConfigured = true
	}
	if marketplaceConfigured {
		installed, err := listInstalledCodexPlugins(ctx, codexExecutable, runner)
		if err != nil {
			return err
		}
		for _, plugin := range installed {
			if plugin.Installed && isPhaseCodexPluginSelector(plugin.PluginID) {
				if _, err := runner(ctx, codexExecutable, "plugin", "remove", plugin.PluginID, "--json"); err != nil {
					return fmt.Errorf("remove Phase Codex plugin: %w", err)
				}
			}
		}
	}

	remaining, err := countCodexMarketplaceEntriesWithoutPhase(root)
	if err != nil {
		return err
	}
	if marketplaceConfigured && remaining == 0 {
		if _, err := runner(ctx, codexExecutable, "plugin", "marketplace", "remove", CodexBootstrapMarketplaceName, "--json"); err != nil {
			return fmt.Errorf("remove Phase Codex marketplace registration: %w", err)
		}
	}
	if _, err := removeCodexMarketplaceEntry(root); err != nil {
		return err
	}
	if err := removeCodexOwnedFiles(root, remaining == 0); err != nil {
		return err
	}
	return nil
}

func codexBootstrapHooks(hookExecutable string) codexHookFile {
	command := func(arguments ...string) codexHookHandler {
		return codexHookHandler{
			Type:           "command",
			Command:        codexPluginCommand(hookExecutable, false, arguments...),
			CommandWindows: codexPluginCommand(hookExecutable, true, arguments...),
		}
	}
	sessionStart := command("ai", "__codex-hook")
	sessionStart.Timeout = 45
	sessionStart.StatusMessage = "Preparing Phase AI"
	sessionStart.AdditionalContextLimit = 1200
	guard := command("ai", "__codex-event", "guard")
	guard.Timeout = 45
	guard.StatusMessage = "Checking Phase-managed execution"
	heartbeat := command("ai", "__codex-event", "heartbeat")
	heartbeat.Timeout = 3
	heartbeat.StatusMessage = "Keeping the Phase AI session alive"
	sessionEnd := command("ai", "__codex-event", "session-end")
	sessionEnd.Timeout = 1
	sessionEnd.StatusMessage = "Releasing the Phase AI session"
	return codexHookFile{
		Description: "Make optional Phase-managed execution available without changing ambient shell tools.",
		Hooks: map[string][]codexHookMatcher{
			"SessionStart":     {{Matcher: "startup|resume|clear|compact", Hooks: []codexHookHandler{sessionStart}}},
			"PreToolUse":       {{Matcher: "Bash", Hooks: []codexHookHandler{guard}}},
			"UserPromptSubmit": {{Hooks: []codexHookHandler{heartbeat}}},
			"SessionEnd":       {{Matcher: "other", Hooks: []codexHookHandler{sessionEnd}}},
		},
	}
}

func codexPluginCommand(executable string, windows bool, arguments ...string) string {
	if windows {
		return WindowsShellCommand(append([]string{executable}, arguments...))
	}
	parts := []string{quotePOSIXCommandArgument(executable)}
	for _, argument := range arguments {
		parts = append(parts, quotePOSIXCommandArgument(argument))
	}
	return strings.Join(parts, " ")
}

func quotePOSIXCommandArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func codexPluginSelector() string {
	return CodexBootstrapPluginName + "@" + CodexBootstrapMarketplaceName
}

func isPhaseCodexPluginName(name string) bool {
	return name == CodexBootstrapPluginName
}

func isPhaseCodexPluginSelector(selector string) bool {
	return selector == codexPluginSelector()
}

func claimCodexMarketplace(root string) error {
	info, err := os.Stat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("create Codex bootstrap marketplace: %w", err)
		}
	case err != nil:
		return fmt.Errorf("inspect Codex bootstrap marketplace: %w", err)
	case !info.IsDir():
		return errors.New("Codex bootstrap marketplace path is not a directory")
	}

	markerPath := filepath.Join(root, codexBootstrapMarkerName)
	if _, err := os.Stat(markerPath); err == nil {
		if err := validateCodexMarketplaceMarker(root); err != nil {
			return err
		}
		return writeCodexMarketplaceMarker(markerPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Codex marketplace ownership marker: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("inspect Codex bootstrap marketplace contents: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("refusing to claim a non-empty Codex marketplace directory not owned by Phase")
	}
	if err := writeCodexMarketplaceMarker(markerPath); err != nil {
		return fmt.Errorf("write Codex marketplace ownership marker: %w", err)
	}
	return nil
}

func validateCodexMarketplaceOwnership(root string) error {
	if err := validateCodexMarketplaceMarker(root); err != nil {
		return err
	}
	foundManifest := false
	for _, name := range []string{CodexBootstrapPluginName} {
		manifestPayload, err := os.ReadFile(filepath.Join(root, "plugins", name, ".codex-plugin", "plugin.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read Phase Codex plugin manifest: %w", err)
		}
		var manifest codexPluginManifest
		if err := json.Unmarshal(manifestPayload, &manifest); err != nil || manifest.Name != name {
			return errors.New("refusing to manage a Codex plugin not owned by Phase")
		}
		foundManifest = true
	}
	if !foundManifest {
		return errors.New("Phase Codex plugin manifest is missing")
	}
	_, entries, err := readCodexMarketplace(root)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range entries {
		if isPhaseCodexPluginName(marketplaceEntryName(entry)) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("Phase Codex marketplace entry is missing")
	}
	return nil
}

func validateCodexMarketplaceMarker(root string) error {
	if root == "" {
		return errors.New("Codex bootstrap marketplace path is required")
	}
	payload, err := os.ReadFile(filepath.Join(root, codexBootstrapMarkerName))
	if err != nil {
		return fmt.Errorf("read Codex marketplace ownership marker: %w", err)
	}
	var marker codexMarketplaceMarker
	if err := json.Unmarshal(payload, &marker); err != nil || marker.Owner != "phase-cli" ||
		marker.Marketplace != CodexBootstrapMarketplaceName || !isPhaseCodexPluginName(marker.Plugin) ||
		(marker.AdapterProtocol != "" && marker.AdapterProtocol != HarnessAdapterProtocolVersion) {
		return errors.New("refusing to manage a Codex marketplace not owned by Phase")
	}
	return nil
}

func writeCodexMarketplaceMarker(path string) error {
	return writeJSONFile(path, codexMarketplaceMarker{
		Owner: "phase-cli", Marketplace: CodexBootstrapMarketplaceName, Plugin: CodexBootstrapPluginName,
		AdapterProtocol: HarnessAdapterProtocolVersion,
	}, 0o600)
}

func codexBootstrapPresent(root string) (bool, error) {
	markerPath := filepath.Join(root, codexBootstrapMarkerName)
	markerExists, err := pathExists(markerPath)
	if err != nil {
		return false, err
	}
	pluginExists := false
	for _, name := range []string{CodexBootstrapPluginName} {
		exists, err := pathExists(filepath.Join(root, "plugins", name, ".codex-plugin", "plugin.json"))
		if err != nil {
			return false, err
		}
		pluginExists = pluginExists || exists
	}
	if !markerExists && !pluginExists {
		return false, nil
	}
	if !markerExists {
		return false, errors.New("refusing to remove a Codex plugin without the Phase ownership marker")
	}
	if err := validateCodexMarketplaceMarker(root); err != nil {
		return false, err
	}
	_, entries, err := readCodexMarketplace(root)
	if err != nil {
		return false, err
	}
	hasEntry := false
	for _, entry := range entries {
		if isPhaseCodexPluginName(marketplaceEntryName(entry)) {
			hasEntry = true
			break
		}
	}
	if !pluginExists && !hasEntry {
		return false, nil
	}
	if pluginExists != hasEntry {
		return false, errors.New("refusing to remove an incomplete Phase Codex plugin installation")
	}
	return true, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("inspect %s: %w", path, err)
}

func upsertCodexMarketplace(root string) error {
	document, entries, err := readCodexMarketplace(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if document == nil {
		document = make(map[string]json.RawMessage)
		name, _ := json.Marshal(CodexBootstrapMarketplaceName)
		document["name"] = name
		presentation, _ := json.Marshal(map[string]string{"displayName": "Phase"})
		document["interface"] = presentation
	}
	entryPayload, err := json.Marshal(codexMarketplaceEntry{
		Name:     CodexBootstrapPluginName,
		Source:   codexMarketplaceSource{Source: "local", Path: "./plugins/" + CodexBootstrapPluginName},
		Policy:   codexMarketplacePolicy{Installation: "AVAILABLE", Authentication: "ON_INSTALL"},
		Category: "Engineering",
	})
	if err != nil {
		return err
	}
	updated := make([]json.RawMessage, 0, len(entries)+1)
	found := false
	for _, entry := range entries {
		if isPhaseCodexPluginName(marketplaceEntryName(entry)) {
			if !found {
				updated = append(updated, entryPayload)
				found = true
			}
			continue
		}
		updated = append(updated, entry)
	}
	if !found {
		updated = append(updated, entryPayload)
	}
	plugins, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	document["plugins"] = plugins
	if err := writeJSONFile(codexMarketplaceManifestPath(root), document, 0o600); err != nil {
		return fmt.Errorf("write Phase Codex marketplace: %w", err)
	}
	return nil
}

func removeCodexMarketplaceEntry(root string) (int, error) {
	document, entries, err := readCodexMarketplace(root)
	if err != nil {
		return 0, err
	}
	updated := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		if !isPhaseCodexPluginName(marketplaceEntryName(entry)) {
			updated = append(updated, entry)
		}
	}
	plugins, err := json.Marshal(updated)
	if err != nil {
		return 0, err
	}
	document["plugins"] = plugins
	if err := writeJSONFile(codexMarketplaceManifestPath(root), document, 0o600); err != nil {
		return 0, fmt.Errorf("update Phase Codex marketplace: %w", err)
	}
	return len(updated), nil
}

func countCodexMarketplaceEntriesWithoutPhase(root string) (int, error) {
	_, entries, err := readCodexMarketplace(root)
	if err != nil {
		return 0, err
	}
	remaining := 0
	for _, entry := range entries {
		if !isPhaseCodexPluginName(marketplaceEntryName(entry)) {
			remaining++
		}
	}
	return remaining, nil
}

func readCodexMarketplace(root string) (map[string]json.RawMessage, []json.RawMessage, error) {
	payload, err := os.ReadFile(codexMarketplaceManifestPath(root))
	if err != nil {
		return nil, nil, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, nil, fmt.Errorf("decode Phase Codex marketplace: %w", err)
	}
	var name string
	if err := json.Unmarshal(document["name"], &name); err != nil || name != CodexBootstrapMarketplaceName {
		return nil, nil, errors.New("refusing to modify a Codex marketplace with an unexpected name")
	}
	var entries []json.RawMessage
	if payload, ok := document["plugins"]; ok {
		if err := json.Unmarshal(payload, &entries); err != nil {
			return nil, nil, fmt.Errorf("decode Phase Codex marketplace entries: %w", err)
		}
	}
	return document, entries, nil
}

func marketplaceEntryName(entry json.RawMessage) string {
	var value struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(entry, &value)
	return value.Name
}

func codexMarketplaceManifestPath(root string) string {
	return filepath.Join(root, ".agents", "plugins", "marketplace.json")
}

func writePrivateTextFile(path, content string) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".phase-plugin-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func hashRegularFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return "", errors.New("Phase executable must be a bounded regular file")
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, info.Size()+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if written != info.Size() {
		return "", errors.New("Phase executable changed while being fingerprinted")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func listCodexMarketplaces(ctx context.Context, codexExecutable string, runner codexCommandRunner) ([]codexMarketplaceInfo, error) {
	payload, err := runner(ctx, codexExecutable, "plugin", "marketplace", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("list Codex marketplaces: %w", err)
	}
	var response codexMarketplaceList
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("decode Codex marketplace list: %w", err)
	}
	return response.Marketplaces, nil
}

func listInstalledCodexPlugins(ctx context.Context, codexExecutable string, runner codexCommandRunner) ([]codexInstalledPlugin, error) {
	payload, err := runner(ctx, codexExecutable, "plugin", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("list installed Codex plugins: %w", err)
	}
	var response codexPluginList
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("decode installed Codex plugins: %w", err)
	}
	return response.Installed, nil
}

func runCodexCommand(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 4096 {
			message = message[:4096]
		}
		if message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func sameLocalPath(left, right string) bool {
	leftPath, err := filepath.Abs(left)
	if err != nil {
		return false
	}
	rightPath, err := filepath.Abs(right)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(leftPath); err == nil {
		leftPath = resolved
	}
	if resolved, err := filepath.EvalSymlinks(rightPath); err == nil {
		rightPath = resolved
	}
	return filepath.Clean(leftPath) == filepath.Clean(rightPath)
}

func removeCodexOwnedFiles(root string, removeMarketplaceFiles bool) error {
	for _, name := range []string{CodexBootstrapPluginName} {
		pluginRoot := filepath.Join(root, "plugins", name)
		if err := os.RemoveAll(pluginRoot); err != nil {
			return fmt.Errorf("remove Phase Codex plugin source: %w", err)
		}
	}
	if removeMarketplaceFiles {
		for _, path := range []string{codexMarketplaceManifestPath(root), filepath.Join(root, codexBootstrapMarkerName)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove Phase Codex marketplace file: %w", err)
			}
		}
		for _, directory := range []string{
			filepath.Join(root, ".agents", "plugins"),
			filepath.Join(root, ".agents"),
			filepath.Join(root, "plugins"),
			root,
		} {
			if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) && !isDirectoryNotEmpty(err) {
				return fmt.Errorf("remove empty Phase Codex marketplace directory: %w", err)
			}
		}
	}
	return nil
}

func isDirectoryNotEmpty(err error) bool {
	return errors.Is(err, os.ErrExist) || strings.Contains(strings.ToLower(err.Error()), "not empty")
}
