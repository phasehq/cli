package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	PhaseCloudAPIHost = "https://console.phase.dev"
	PhaseEnvConfig    = ".phase.json"
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
	Email            string  `json:"email,omitempty"`
	OrganizationID   *string `json:"organization_id,omitempty"`
	OrganizationName *string `json:"organization_name,omitempty"`
	WrappedKeyShare  *string `json:"wrapped_key_share,omitempty"`
	Token            string  `json:"token,omitempty"`
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
	if token := os.Getenv("PHASE_SERVICE_TOKEN"); token != "" {
		host := os.Getenv("PHASE_HOST")
		if host == "" {
			host = PhaseCloudAPIHost
		}
		return host, nil
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
