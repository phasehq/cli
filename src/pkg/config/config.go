package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	data, err := os.ReadFile(ConfigFilePath)
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
	return os.WriteFile(ConfigFilePath, data, 0600)
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
	if host := os.Getenv("PHASE_HOST"); host != "" {
		return host, nil
	}

	if os.Getenv("PHASE_SERVICE_TOKEN") != "" {
		return PhaseCloudAPIHost, nil
	}

	config, err := LoadConfig()
	if err != nil {
		return "", fmt.Errorf("config file not found and no PHASE_SERVICE_TOKEN environment variable set")
	}

	for _, user := range config.PhaseUsers {
		if user.ID == config.DefaultUser {
			return user.Host, nil
		}
	}
	return "", fmt.Errorf("no user found in config.json with id: %s", config.DefaultUser)
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

func GetDefaultUserOrg() (string, error) {
	user, err := GetDefaultUser()
	if err != nil {
		return "", err
	}
	if user.OrganizationName != nil && *user.OrganizationName != "" {
		return *user.OrganizationName, nil
	}
	return "", fmt.Errorf("no organization name found for default user")
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

const (
	AIConfigVersion  = "3"
	AIProxyModeLocal = "local"
)

type AIConfig struct {
	Version           string   `json:"version"`
	Enabled           bool     `json:"enabled"`
	ProxyMode         string   `json:"proxyMode"`
	MaskSecretValues  bool     `json:"maskSecretValues"`
	DefaultWorkflowID string   `json:"defaultWorkflowId,omitempty"`
	SkillInstallPath  string   `json:"skillInstallPath,omitempty"`
	HarnessID         string   `json:"harnessId,omitempty"`
	SkillInstallPaths []string `json:"skillInstallPaths,omitempty"`
	HarnessIDs        []string `json:"harnessIds,omitempty"`
}

func LoadAIConfig() *AIConfig {
	data, err := os.ReadFile(AIConfigPath)
	if err != nil {
		return nil
	}
	var raw struct {
		Version           string   `json:"version"`
		Enabled           *bool    `json:"enabled"`
		ProxyMode         string   `json:"proxyMode"`
		DefaultWorkflowID string   `json:"defaultWorkflowId"`
		SkillInstallPath  string   `json:"skillInstallPath"`
		HarnessID         string   `json:"harnessId"`
		SkillInstallPaths []string `json:"skillInstallPaths"`
		HarnessIDs        []string `json:"harnessIds"`
		MaskSecretValues  *bool    `json:"maskSecretValues"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	// Version 1 files hold only the masking preference. They are rewritten in
	// the current format on first load.
	if raw.Version == "" || raw.Version == "1" {
		migrated := &AIConfig{
			Version:          AIConfigVersion,
			Enabled:          true,
			ProxyMode:        AIProxyModeLocal,
			MaskSecretValues: maskPreference(raw.MaskSecretValues),
		}
		_ = SaveAIConfig(migrated)
		return migrated
	}
	if raw.Version != AIConfigVersion || raw.Enabled == nil {
		return nil
	}

	mode := raw.ProxyMode
	if mode == "" {
		mode = AIProxyModeLocal
	}
	return &AIConfig{
		Version:           AIConfigVersion,
		Enabled:           *raw.Enabled,
		ProxyMode:         mode,
		MaskSecretValues:  maskPreference(raw.MaskSecretValues),
		DefaultWorkflowID: raw.DefaultWorkflowID,
		SkillInstallPath:  raw.SkillInstallPath,
		HarnessID:         raw.HarnessID,
		SkillInstallPaths: uniqueNonEmpty(raw.SkillInstallPaths, raw.SkillInstallPath),
		HarnessIDs:        uniqueNonEmpty(raw.HarnessIDs, raw.HarnessID),
	}
}

// ConfiguredHarnessIDs returns every harness configured for automatic Phase
// integration. HarnessID holds the most recently selected harness; callers
// should use the plural list through this helper.
func (cfg *AIConfig) ConfiguredHarnessIDs() []string {
	if cfg == nil {
		return nil
	}
	return uniqueNonEmpty(cfg.HarnessIDs, cfg.HarnessID)
}

// ConfiguredSkillInstallPaths returns every skill copy Phase should keep
// refreshed. SkillInstallPath is retained as a backwards-compatible alias for
// the most recently selected target.
func (cfg *AIConfig) ConfiguredSkillInstallPaths() []string {
	if cfg == nil {
		return nil
	}
	return uniqueNonEmpty(cfg.SkillInstallPaths, cfg.SkillInstallPath)
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
	configured := cfg.ConfiguredHarnessIDs()
	if len(configured) == 0 {
		return false
	}
	for _, candidate := range configured {
		if candidate == harness {
			return true
		}
	}
	return false
}

// AddHarnessInstallation records one additional integration without replacing
// any previously installed harness or skill target.
func (cfg *AIConfig) AddHarnessInstallation(harness, skillPath string) {
	if cfg == nil {
		return
	}
	cfg.HarnessIDs = uniqueNonEmpty(cfg.ConfiguredHarnessIDs(), harness)
	cfg.SkillInstallPaths = uniqueNonEmpty(cfg.ConfiguredSkillInstallPaths(), skillPath)
	// Keep the singular fields for older CLI builds and human-readable config.
	if harness != "" {
		cfg.HarnessID = harness
	}
	if skillPath != "" {
		cfg.SkillInstallPath = skillPath
	}
}

// ClearHarnessInstallations forgets adapters and skill copies after a
// successful global disable. Proxy mode and Workflow defaults are retained for
// the next enable.
func (cfg *AIConfig) ClearHarnessInstallations() {
	if cfg == nil {
		return
	}
	cfg.HarnessID = ""
	cfg.HarnessIDs = nil
	cfg.SkillInstallPath = ""
	cfg.SkillInstallPaths = nil
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
	if cfg.ProxyMode != AIProxyModeLocal {
		return fmt.Errorf("unsupported AI proxy mode: %s", cfg.ProxyMode)
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
	return os.WriteFile(AIConfigPath, data, 0600)
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

// maskPreference reads the stored secret-visibility choice; a missing value
// masks, which is the safer default.
func maskPreference(stored *bool) bool {
	if stored == nil {
		return true
	}
	return *stored
}
