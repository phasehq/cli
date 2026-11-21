package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type PhaseJSONConfig struct {
	Version         string `json:"version"`
	PhaseApp        string `json:"phaseApp"`
	AppID           string `json:"appId"`
	DefaultEnv      string `json:"defaultEnv"`
	EnvID           string `json:"envId"`
	MonorepoSupport bool   `json:"monorepoSupport"`
}

func FindPhaseConfig(maxDepth int) *PhaseJSONConfig {
	// Check env var override for search depth
	if envDepth := os.Getenv("PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH"); envDepth != "" {
		if d, err := strconv.Atoi(envDepth); err == nil {
			maxDepth = d
		}
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return nil
	}
	originalDir := currentDir

	for i := 0; i <= maxDepth; i++ {
		configPath := filepath.Join(currentDir, PhaseEnvConfig)
		data, err := os.ReadFile(configPath)
		if err == nil {
			var config PhaseJSONConfig
			if err := json.Unmarshal(data, &config); err == nil {
				// Only use config from parent dirs if monorepoSupport is true
				if currentDir == originalDir || config.MonorepoSupport {
					return &config
				}
			}
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			break
		}
		currentDir = parentDir
	}
	return nil
}

func WritePhaseConfig(config *PhaseJSONConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	// A checkout can ship .phase.json as a link to a file outside it; replace
	// only a regular file, and by rename, so nothing outside is written.
	if info, err := os.Lstat(PhaseEnvConfig); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (it may be a symbolic link); remove it and run the command again", PhaseEnvConfig)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomically(PhaseEnvConfig, data)
}
