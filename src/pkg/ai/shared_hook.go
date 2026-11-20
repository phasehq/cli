package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// HarnessAdapterProtocolVersion versions the small, harness-facing adapter
	// contract. Provider support and runtime discovery are deliberately not part
	// of this version and can evolve without reinstalling harness integrations.
	HarnessAdapterProtocolVersion = "1.0.0"
	// HelperIPCProtocolVersion independently versions the adapter-to-helper IPC.
	// A helper implementation may be refreshed in place while this stays stable.
	HelperIPCProtocolVersion = "1.0.0"

	sharedHookMetadataSchemaVersion = 1
	sharedHookOwner                 = "phase-cli"
)

type SharedHookInstall struct {
	ExecutablePath string
	MetadataPath   string
	Digest         string
	Changed        bool
	RepairedDrift  bool
}

type sharedHookMetadata struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Owner           string `json:"owner"`
	AdapterProtocol string `json:"adapterProtocol"`
	HelperProtocol  string `json:"helperProtocol"`
	SHA256          string `json:"sha256"`
}

// DefaultSharedHookExecutablePath is the stable entrypoint used by every
// harness adapter. Its major-versioned filename lets a future incompatible
// adapter coexist with v1 without changing an already-installed integration.
func DefaultSharedHookExecutablePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	name := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(home, ".phase", "ai", "bin", name), nil
}

func sharedHookMetadataPath(executablePath string) string {
	return executablePath + ".metadata.json"
}

// InstallSharedHookExecutable installs or refreshes the single Phase helper
// shared by all local harness adapters. The digest is ownership/drift metadata,
// not a plugin version: routine CLI updates can replace the implementation
// without making the stable v1 adapter contract appear to change.
func InstallSharedHookExecutable(source string) (SharedHookInstall, error) {
	installation := SharedHookInstall{}
	if !filepath.IsAbs(source) {
		return installation, errors.New("Phase executable path for Agent hooks must be absolute")
	}
	destination, err := DefaultSharedHookExecutablePath()
	if err != nil {
		return installation, err
	}
	installation.ExecutablePath = destination
	installation.MetadataPath = sharedHookMetadataPath(destination)

	sourceDigest, err := hashRegularFile(source)
	if err != nil {
		return installation, fmt.Errorf("fingerprint Phase hook source: %w", err)
	}
	installation.Digest = sourceDigest

	destinationExists, err := pathExists(destination)
	if err != nil {
		return installation, err
	}
	metadataExists, err := pathExists(installation.MetadataPath)
	if err != nil {
		return installation, err
	}

	var previous sharedHookMetadata
	if destinationExists || metadataExists {
		if !metadataExists {
			return installation, errors.New("refusing to replace a shared Phase hook without its ownership metadata")
		}
		payload, readErr := os.ReadFile(installation.MetadataPath)
		if readErr != nil || json.Unmarshal(payload, &previous) != nil ||
			previous.SchemaVersion != sharedHookMetadataSchemaVersion || previous.Owner != sharedHookOwner ||
			previous.AdapterProtocol != HarnessAdapterProtocolVersion ||
			previous.HelperProtocol != HelperIPCProtocolVersion {
			return installation, errors.New("refusing to replace a shared Agent hook not owned by this Phase adapter protocol")
		}
		if destinationExists {
			currentDigest, digestErr := hashRegularFile(destination)
			if digestErr != nil {
				return installation, fmt.Errorf("inspect installed shared Phase hook: %w", digestErr)
			}
			installation.RepairedDrift = currentDigest != previous.SHA256
			installation.Changed = currentDigest != sourceDigest
		} else {
			installation.RepairedDrift = true
			installation.Changed = true
		}
	} else {
		installation.Changed = true
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return installation, fmt.Errorf("create shared Phase hook directory: %w", err)
	}
	metadata := sharedHookMetadata{
		SchemaVersion: sharedHookMetadataSchemaVersion,
		Owner:         sharedHookOwner, AdapterProtocol: HarnessAdapterProtocolVersion,
		HelperProtocol: HelperIPCProtocolVersion, SHA256: sourceDigest,
	}
	// Write ownership first. If the following atomic executable replacement is
	// interrupted, the next enable/update can recognize and repair the drift.
	if err := writeJSONFile(installation.MetadataPath, metadata, 0o600); err != nil {
		return installation, fmt.Errorf("write shared Phase hook metadata: %w", err)
	}
	if filepath.Clean(source) != filepath.Clean(destination) && installation.Changed {
		if err := copyClaudeHookExecutable(source, destination); err != nil {
			return installation, fmt.Errorf("install shared Phase hook executable: %w", err)
		}
	} else if filepath.Clean(source) == filepath.Clean(destination) {
		installation.Changed = installation.RepairedDrift
	}

	installedDigest, err := hashRegularFile(destination)
	if err != nil {
		return installation, fmt.Errorf("verify shared Phase hook executable: %w", err)
	}
	if installedDigest != sourceDigest {
		return installation, errors.New("shared Phase hook does not match the current CLI executable")
	}
	return installation, nil
}

// UninstallSharedHookExecutable removes only the v1 helper backed by valid
// Phase ownership metadata. Harness adapters are removed first by ai disable.
func UninstallSharedHookExecutable() error {
	executable, err := DefaultSharedHookExecutablePath()
	if err != nil {
		return err
	}
	metadataPath := sharedHookMetadataPath(executable)
	payload, err := os.ReadFile(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat(executable); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return errors.New("refusing to remove a shared Phase hook without its ownership metadata")
	}
	if err != nil {
		return fmt.Errorf("read shared Phase hook metadata: %w", err)
	}
	var metadata sharedHookMetadata
	if json.Unmarshal(payload, &metadata) != nil || metadata.SchemaVersion != sharedHookMetadataSchemaVersion ||
		metadata.Owner != sharedHookOwner || metadata.AdapterProtocol != HarnessAdapterProtocolVersion ||
		metadata.HelperProtocol != HelperIPCProtocolVersion {
		return errors.New("refusing to remove a shared Agent hook not owned by this Phase adapter protocol")
	}
	for _, path := range []string{executable, metadataPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove shared Phase hook %s: %w", path, err)
		}
	}
	_ = os.Remove(filepath.Dir(executable))
	return nil
}
