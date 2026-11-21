package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	PhaseCloudAPIHost = "https://console.phase.dev"
	PhaseEnvConfig    = ".phase.json"
	PrincipalAgent    = "agent"
)

var (
	PhaseSecretsDir = filepath.Join(homeDir(), ".phase", "secrets")
	ConfigFilePath  = filepath.Join(PhaseSecretsDir, "config.json")
)

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

type UserConfig struct {
	Host             string  `json:"host"`
	ID               string  `json:"id"`
	PrincipalType    string  `json:"principal_type,omitempty"`
	PrincipalID      string  `json:"principal_id,omitempty"`
	PrincipalName    string  `json:"principal_name,omitempty"`
	WorkflowID       string  `json:"workflow_id,omitempty"`
	WorkflowName     string  `json:"workflow_name,omitempty"`
	Email            string  `json:"email,omitempty"`
	OrganizationID   *string `json:"organization_id,omitempty"`
	OrganizationName *string `json:"organization_name,omitempty"`
	WrappedKeyShare  *string `json:"wrapped_key_share,omitempty"`
	Token            string  `json:"token,omitempty"`
}

// IsAgentPrincipal reports whether this login was made with an Agent token.
func (u UserConfig) IsAgentPrincipal() bool {
	return u.PrincipalType == PrincipalAgent
}

type Config struct {
	DefaultUser string       `json:"default-user"`
	PhaseUsers  []UserConfig `json:"phase-users"`
}

func LoadConfig() (*Config, error) {
	data, err := readConfigFile(ConfigFilePath)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}
	return &config, nil
}

func SaveConfig(config *Config) error {
	if err := os.MkdirAll(PhaseSecretsDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	return writeFileAtomically(ConfigFilePath, data)
}

func GetDefaultUser() (*UserConfig, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable")
	}
	if config.DefaultUser == "" {
		return nil, fmt.Errorf("no default user set")
	}
	for _, user := range config.PhaseUsers {
		if user.ID == config.DefaultUser {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("no user found in config.json with id: %s", config.DefaultUser)
}

func GetDefaultAccountID(allIDs bool) ([]string, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable")
	}
	if allIDs {
		var ids []string
		for _, user := range config.PhaseUsers {
			ids = append(ids, user.ID)
		}
		return ids, nil
	}
	return []string{config.DefaultUser}, nil
}

func GetDefaultUserHost() (string, error) {
	override := os.Getenv("PHASE_HOST")
	if os.Getenv("PHASE_SERVICE_TOKEN") != "" {
		if override != "" {
			return override, nil
		}
		return PhaseCloudAPIHost, nil
	}

	config, err := LoadConfig()
	if err != nil {
		if override != "" {
			return override, nil
		}
		return "", fmt.Errorf("config file not found and no PHASE_SERVICE_TOKEN environment variable set")
	}
	if config.DefaultUser == "" && override != "" {
		return override, nil
	}

	for _, user := range config.PhaseUsers {
		if user.ID == config.DefaultUser {
			// A saved login's token is only ever sent to the host it was saved
			// with, so an override that names another host cannot redirect it.
			if override != "" && !SameHost(override, user.Host) {
				return "", SavedLoginHostError(override, user.Host)
			}
			return user.Host, nil
		}
	}
	return "", fmt.Errorf("no user found in config.json with id: %s", config.DefaultUser)
}

// ValidAccountID reports whether id is safe to use as one component of a
// local path and a keystore name: the Console's ids are UUIDs, and an Agent
// login's is "agent-" and hex.
func ValidAccountID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// SavedLoginHostError refuses a PHASE_HOST that names another host than the
// one the saved login belongs to.
func SavedLoginHostError(override, saved string) error {
	return fmt.Errorf("PHASE_HOST is set to %s, but the saved login belongs to %s. Unset PHASE_HOST, or log in to %s with phase auth", override, saved, override)
}

// SameHost reports whether two Phase host URLs name the same Console.
func SameHost(a, b string) bool {
	normalize := func(host string) string {
		return strings.TrimRight(strings.TrimSpace(host), "/")
	}
	return strings.EqualFold(normalize(a), normalize(b))
}

func GetDefaultUserToken() (string, error) {
	config, err := LoadConfig()
	if err != nil {
		return "", fmt.Errorf("config file not found. Please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable")
	}
	if config.DefaultUser == "" {
		return "", fmt.Errorf("default user ID is missing in the config file")
	}
	for _, user := range config.PhaseUsers {
		if user.ID == config.DefaultUser {
			if user.Token == "" {
				return "", fmt.Errorf("token for the default user (ID: %s) is not found in the config file", config.DefaultUser)
			}
			return user.Token, nil
		}
	}
	return "", fmt.Errorf("default user not found in the config file")
}

func AddUser(user UserConfig) error {
	config, err := LoadConfig()
	if err != nil {
		config = &Config{PhaseUsers: []UserConfig{}}
	}
	// Replace existing user with same ID or add new
	found := false
	for i, u := range config.PhaseUsers {
		if u.ID == user.ID {
			config.PhaseUsers[i] = user
			found = true
			break
		}
	}
	if !found {
		config.PhaseUsers = append(config.PhaseUsers, user)
	}
	config.DefaultUser = user.ID
	return SaveConfig(config)
}

func SetDefaultUser(accountID string) error {
	config, err := LoadConfig()
	if err != nil {
		return err
	}
	found := false
	for _, u := range config.PhaseUsers {
		if u.ID == accountID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no user found with ID: %s", accountID)
	}
	config.DefaultUser = accountID
	return SaveConfig(config)
}

var AIConfigPath = filepath.Join(homeDir(), ".phase", "ai.json")

const AIConfigVersion = "3"

// releasedAIConfigVersion is what CLI v2.3.3 and earlier wrote.
const releasedAIConfigVersion = "1"

type AIConfig struct {
	Version           string   `json:"version"`
	Enabled           bool     `json:"enabled"`
	DefaultWorkflowID string   `json:"defaultWorkflowId,omitempty"`
	SkillInstallPaths []string `json:"skillInstallPaths,omitempty"`
	HarnessIDs        []string `json:"harnessIds,omitempty"`
	// OpenCode's root follows its environment, so refresh and disable use the
	// plugin paths enable wrote rather than the current environment's.
	OpenCodePlugins []string `json:"openCodePlugins,omitempty"`
}

func LoadAIConfig() *AIConfig {
	data, err := readConfigFile(AIConfigPath)
	if err != nil {
		return nil
	}
	var raw struct {
		Version           string   `json:"version"`
		Enabled           *bool    `json:"enabled"`
		DefaultWorkflowID string   `json:"defaultWorkflowId"`
		SkillInstallPaths []string `json:"skillInstallPaths"`
		HarnessIDs        []string `json:"harnessIds"`
		OpenCodePlugins   []string `json:"openCodePlugins"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if raw.Version == releasedAIConfigVersion {
		// The released CLI wrote only a version and a masking choice, and the
		// file's presence meant AI mode was on. It installed a skill and no
		// harness integration, so it reads as enabled with no harnesses.
		return &AIConfig{Version: AIConfigVersion, Enabled: true}
	}
	if raw.Version != AIConfigVersion || raw.Enabled == nil {
		return nil
	}
	return &AIConfig{
		Version:           AIConfigVersion,
		Enabled:           *raw.Enabled,
		DefaultWorkflowID: raw.DefaultWorkflowID,
		SkillInstallPaths: uniqueNonEmpty(raw.SkillInstallPaths),
		HarnessIDs:        uniqueNonEmpty(raw.HarnessIDs),
		OpenCodePlugins:   uniqueNonEmpty(raw.OpenCodePlugins),
	}
}

// ConfiguredHarnessIDs returns every harness configured for automatic Phase
// integration.
func (cfg *AIConfig) ConfiguredHarnessIDs() []string {
	if cfg == nil {
		return nil
	}
	return uniqueNonEmpty(cfg.HarnessIDs)
}

// ConfiguredSkillInstallPaths returns every skill copy Phase should keep
// refreshed.
func (cfg *AIConfig) ConfiguredSkillInstallPaths() []string {
	if cfg == nil {
		return nil
	}
	return uniqueNonEmpty(cfg.SkillInstallPaths)
}

// HarnessEnabled reports whether an installed harness integration may start
// Phase. An empty v3 list means no automatic harness is authorized.
func (cfg *AIConfig) HarnessEnabled(harness string) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}
	return cfg.HarnessConfigured(harness)
}

// HarnessConfigured reports whether the harness belongs to this setup without
// considering the global enabled bit. It is used during disable-time cleanup.
func (cfg *AIConfig) HarnessConfigured(harness string) bool {
	if cfg == nil {
		return false
	}
	return slices.Contains(cfg.ConfiguredHarnessIDs(), harness)
}

// AddHarnessInstallation records one additional integration without replacing
// any previously installed harness or skill target.
func (cfg *AIConfig) AddHarnessInstallation(harness, skillPath string) {
	if cfg == nil {
		return
	}
	cfg.HarnessIDs = uniqueNonEmpty(cfg.ConfiguredHarnessIDs(), harness)
	cfg.SkillInstallPaths = uniqueNonEmpty(cfg.ConfiguredSkillInstallPaths(), skillPath)
}

// ClearHarnessInstallations forgets adapters and skill copies after a
// successful global disable. The Workflow default is retained for the next
// enable.
func (cfg *AIConfig) ClearHarnessInstallations() {
	if cfg == nil {
		return
	}
	cfg.HarnessIDs = nil
	cfg.SkillInstallPaths = nil
	cfg.OpenCodePlugins = nil
}

// RecordOpenCodePlugin adds path to the saved config's OpenCode plugins. Enable
// records a plugin before writing it, so disable finds it even if a later step
// of enable fails.
func RecordOpenCodePlugin(path string) error {
	cfg := LoadAIConfig()
	if cfg == nil {
		// Never replace an ai.json this build cannot read: redaction fails
		// closed on it, and it may hold a newer CLI's settings.
		if _, err := os.Stat(AIConfigPath); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Phase AI configuration cannot be read")
		}
		cfg = &AIConfig{}
	}
	if slices.Contains(cfg.OpenCodePlugins, path) {
		return nil
	}
	cfg.OpenCodePlugins = append(cfg.OpenCodePlugins, path)
	return SaveAIConfig(cfg)
}

func uniqueNonEmpty(values []string, extras ...string) []string {
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(values)+len(extras))
	for _, item := range append(append([]string(nil), values...), extras...) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

func SaveAIConfig(cfg *AIConfig) error {
	if cfg == nil {
		return fmt.Errorf("AI config is required")
	}
	cfg.Version = AIConfigVersion
	cfg.HarnessIDs = cfg.ConfiguredHarnessIDs()
	cfg.SkillInstallPaths = cfg.ConfiguredSkillInstallPaths()
	if err := os.MkdirAll(filepath.Dir(AIConfigPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(AIConfigPath, data)
}

// readConfigFile retries a read that races writeFileAtomically: Windows refuses
// to open the file for the instant its replacement is renamed over it.
func readConfigFile(path string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, err := os.ReadFile(path)
		if err == nil || runtime.GOOS != "windows" || errors.Is(err, os.ErrNotExist) || attempt == 20 {
			return data, err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// writeFileAtomically replaces path with one rename, so a concurrent reader
// sees the previous or the new file and never a truncated one.
func writeFileAtomically(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	for attempt := 0; ; attempt++ {
		err = os.Rename(temporary.Name(), path)
		// Windows cannot replace a file while a reader has it open; reads are brief.
		if err == nil || runtime.GOOS != "windows" || attempt == 50 {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func RemoveUser(id string) error {
	config, err := LoadConfig()
	if err != nil {
		return err
	}
	var remaining []UserConfig
	for _, u := range config.PhaseUsers {
		if u.ID != id {
			remaining = append(remaining, u)
		}
	}
	config.PhaseUsers = remaining
	if len(remaining) == 0 {
		config.DefaultUser = ""
	} else if config.DefaultUser == id {
		config.DefaultUser = remaining[0].ID
	}
	return SaveConfig(config)
}
