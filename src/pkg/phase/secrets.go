package phase

import (
	"encoding/json"
	"fmt"
	"strings"

	localnetwork "github.com/phasehq/cli/pkg/network"
	"github.com/phasehq/golang-sdk/phase/crypto"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/phasehq/golang-sdk/phase/network"
)

type SecretResult struct {
	Key          string   `json:"key"`
	Value        string   `json:"value"`
	Overridden   bool     `json:"overridden"`
	Tags         []string `json:"tags"`
	Comment      string   `json:"comment"`
	Path         string   `json:"path"`
	Application  string   `json:"application"`
	Environment  string   `json:"environment"`
	IsDynamic    bool     `json:"is_dynamic,omitempty"`
	DynamicGroup string   `json:"dynamic_group,omitempty"`
}

type GetOptions struct {
	EnvName  string
	AppName  string
	AppID    string
	Keys     []string
	Tag      string
	Path     string
	Dynamic  bool
	Lease    bool
	LeaseTTL *int
}

type CreateOptions struct {
	KeyValuePairs []KeyValuePair
	EnvName       string
	AppName       string
	AppID         string
	Path          string
	OverrideValue string
}

type KeyValuePair struct {
	Key   string
	Value string
}

type UpdateOptions struct {
	EnvName         string
	AppName         string
	AppID           string
	Key             string
	Value           string
	SourcePath      string
	DestinationPath string
	Override        bool
	ToggleOverride  bool
}

type DeleteOptions struct {
	EnvName      string
	AppName      string
	AppID        string
	KeysToDelete []string
	Path         string
}

func (p *Phase) Get(opts GetOptions) ([]SecretResult, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}

	appName, _, envName, envID, publicKey, err := PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return nil, err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return nil, fmt.Errorf("no environment found with id: %s", envID)
	}

	// Decrypt wrapped seed to get env keypair
	wrappedSeed := envKey.WrappedSeed
	userDataMap := appKeyResponseToMap(&userData)
	decryptedSeed, err := p.Decrypt(wrappedSeed, userDataMap)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	envPubKey, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate env key pair: %w", err)
	}
	_ = envPubKey // Use the identity key from the API instead

	// Fetch secrets
	var secrets []map[string]interface{}
	if opts.Dynamic {
		secrets, err = localnetwork.FetchPhaseSecretsWithDynamic(p.TokenType, p.AppToken, envID, p.APIHost, opts.Path, true, opts.Lease, opts.LeaseTTL)
	} else {
		secrets, err = network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.APIHost, opts.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}

	var results []SecretResult
	for _, secret := range secrets {
		// Handle dynamic secrets
		secretType, _ := secret["type"].(string)
		if secretType == "dynamic" {
			dynamicResults := p.processDynamicSecret(secret, envPrivKey, publicKey, appName, envName, opts)
			results = append(results, dynamicResults...)
			continue
		}

		// Check tag filter
		if opts.Tag != "" {
			secretTags := extractStringSlice(secret, "tags")
			if !misc.TagMatches(secretTags, opts.Tag) {
				continue
			}
		}

		// Determine if override is active
		override, hasOverride := secret["override"].(map[string]interface{})
		useOverride := hasOverride && override != nil && getBool(override, "is_active")

		keyToDecrypt, _ := secret["key"].(string)
		var valueToDecrypt string
		if useOverride {
			valueToDecrypt, _ = override["value"].(string)
		} else {
			valueToDecrypt, _ = secret["value"].(string)
		}
		commentToDecrypt, _ := secret["comment"].(string)

		decryptedKey, err := crypto.DecryptAsymmetric(keyToDecrypt, envPrivKey, publicKey)
		if err != nil {
			continue
		}

		decryptedValue, err := crypto.DecryptAsymmetric(valueToDecrypt, envPrivKey, publicKey)
		if err != nil {
			continue
		}

		var decryptedComment string
		if commentToDecrypt != "" {
			decryptedComment, _ = crypto.DecryptAsymmetric(commentToDecrypt, envPrivKey, publicKey)
		}

		secretPath, _ := secret["path"].(string)
		if secretPath == "" {
			secretPath = "/"
		}

		secretTags := extractStringSlice(secret, "tags")

		result := SecretResult{
			Key:         decryptedKey,
			Value:       decryptedValue,
			Overridden:  useOverride,
			Tags:        secretTags,
			Comment:     decryptedComment,
			Path:        secretPath,
			Application: appName,
			Environment: envName,
		}

		// Filter by keys if specified
		if len(opts.Keys) > 0 {
			found := false
			for _, k := range opts.Keys {
				if k == decryptedKey {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (p *Phase) processDynamicSecret(secret map[string]interface{}, envPrivKey, publicKey, appName, envName string, opts GetOptions) []SecretResult {
	var results []SecretResult

	// Build group label
	name, _ := secret["key"].(string)
	if name != "" {
		decName, err := crypto.DecryptAsymmetric(name, envPrivKey, publicKey)
		if err == nil {
			name = decName
		}
	}
	provider, _ := secret["provider"].(string)
	groupLabel := fmt.Sprintf("%s (%s)", name, provider)

	secretPath, _ := secret["path"].(string)
	if secretPath == "" {
		secretPath = "/"
	}

	// Build credential map from lease if present
	credMap := map[string]string{}
	if leaseData, ok := secret["lease"].(map[string]interface{}); ok && leaseData != nil {
		if creds, ok := leaseData["credentials"].([]interface{}); ok {
			for _, c := range creds {
				credEntry, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				encKey, _ := credEntry["key"].(string)
				encVal, _ := credEntry["value"].(string)
				if encKey == "" {
					continue
				}
				decKey, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
				if err != nil {
					continue
				}
				decVal := ""
				if encVal != "" {
					decVal, _ = crypto.DecryptAsymmetric(encVal, envPrivKey, publicKey)
				}
				credMap[decKey] = decVal
			}
		}
	}

	// Process key_map entries
	keyMap, ok := secret["key_map"].([]interface{})
	if !ok {
		return results
	}

	for _, km := range keyMap {
		entry, ok := km.(map[string]interface{})
		if !ok {
			continue
		}
		encKeyName, _ := entry["key_name"].(string)
		if encKeyName == "" {
			continue
		}
		decKeyName, err := crypto.DecryptAsymmetric(encKeyName, envPrivKey, publicKey)
		if err != nil {
			continue
		}

		value := ""
		if v, exists := credMap[decKeyName]; exists {
			value = v
		}

		result := SecretResult{
			Key:          decKeyName,
			Value:        value,
			Path:         secretPath,
			Application:  appName,
			Environment:  envName,
			IsDynamic:    true,
			DynamicGroup: groupLabel,
		}

		if len(opts.Keys) > 0 {
			found := false
			for _, k := range opts.Keys {
				if k == decKeyName {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, result)
	}

	return results
}

func (p *Phase) Create(opts CreateOptions) error {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return fmt.Errorf("no environment found with id: %s", envID)
	}

	// Decrypt salt for key digest
	userDataMap := appKeyResponseToMap(&userData)
	decryptedSalt, err := p.Decrypt(envKey.WrappedSalt, userDataMap)
	if err != nil {
		return fmt.Errorf("failed to decrypt wrapped salt: %w", err)
	}

	path := opts.Path
	if path == "" {
		path = "/"
	}

	var secrets []map[string]interface{}
	for _, pair := range opts.KeyValuePairs {
		encryptedKey, err := crypto.EncryptAsymmetric(pair.Key, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		encryptedValue, err := crypto.EncryptAsymmetric(pair.Value, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		keyDigest, err := crypto.Blake2bDigest(pair.Key, decryptedSalt)
		if err != nil {
			return fmt.Errorf("failed to generate key digest: %w", err)
		}

		secret := map[string]interface{}{
			"key":       encryptedKey,
			"keyDigest": keyDigest,
			"value":     encryptedValue,
			"path":      path,
			"tags":      []string{},
			"comment":   "",
		}

		if opts.OverrideValue != "" {
			encryptedOverride, err := crypto.EncryptAsymmetric(opts.OverrideValue, publicKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt override value: %w", err)
			}
			secret["override"] = map[string]interface{}{
				"value":    encryptedOverride,
				"isActive": true,
			}
		}

		secrets = append(secrets, secret)
	}

	return network.CreatePhaseSecrets(p.TokenType, p.AppToken, envID, secrets, p.APIHost)
}

func (p *Phase) Update(opts UpdateOptions) (string, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return "", fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return "", err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return "", fmt.Errorf("no environment found with id: %s", envID)
	}

	// Fetch secrets from source path
	sourcePath := opts.SourcePath
	secrets, err := network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.APIHost, sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to fetch secrets: %w", err)
	}

	// Decrypt seed to get env keypair
	userDataMap := appKeyResponseToMap(&userData)
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed, userDataMap)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	_, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return "", fmt.Errorf("failed to generate env key pair: %w", err)
	}

	// Find matching secret
	var matchingSecret map[string]interface{}
	for _, secret := range secrets {
		encKey, _ := secret["key"].(string)
		dk, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
		if err != nil {
			continue
		}
		if dk == opts.Key {
			matchingSecret = secret
			break
		}
	}

	if matchingSecret == nil {
		return fmt.Sprintf("Key '%s' doesn't exist in path '%s'.", opts.Key, sourcePath), nil
	}

	// Encrypt key and value
	encryptedKey, err := crypto.EncryptAsymmetric(opts.Key, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	encryptedValue, err := crypto.EncryptAsymmetric(coalesce(opts.Value, ""), publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt value: %w", err)
	}

	// Get key digest
	decryptedSalt, err := p.Decrypt(envKey.WrappedSalt, userDataMap)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wrapped salt: %w", err)
	}

	keyDigest, err := crypto.Blake2bDigest(opts.Key, decryptedSalt)
	if err != nil {
		return "", fmt.Errorf("failed to generate key digest: %w", err)
	}

	// Determine payload value
	payloadValue := encryptedValue
	if opts.Override || opts.ToggleOverride {
		payloadValue, _ = matchingSecret["value"].(string)
	}

	// Determine path
	path := matchingSecret["path"]
	if opts.DestinationPath != "" {
		path = opts.DestinationPath
	}

	secretID, _ := matchingSecret["id"].(string)
	payload := map[string]interface{}{
		"id":        secretID,
		"key":       encryptedKey,
		"keyDigest": keyDigest,
		"value":     payloadValue,
		"tags":      matchingSecret["tags"],
		"comment":   matchingSecret["comment"],
		"path":      path,
	}

	// Handle override logic
	if opts.ToggleOverride {
		override, hasOverride := matchingSecret["override"].(map[string]interface{})
		if !hasOverride || override == nil {
			return "", fmt.Errorf("no override found for key '%s'. Create one first with --override", opts.Key)
		}
		currentState := getBool(override, "is_active")
		payload["override"] = map[string]interface{}{
			"value":    override["value"],
			"isActive": !currentState,
		}
	} else if opts.Override {
		override, hasOverride := matchingSecret["override"].(map[string]interface{})
		if !hasOverride || override == nil {
			payload["override"] = map[string]interface{}{
				"value":    encryptedValue,
				"isActive": true,
			}
		} else {
			val := encryptedValue
			if opts.Value == "" {
				val, _ = override["value"].(string)
			}
			payload["override"] = map[string]interface{}{
				"value":    val,
				"isActive": getBool(override, "is_active"),
			}
		}
	}

	err = network.UpdatePhaseSecrets(p.TokenType, p.AppToken, envID, []map[string]interface{}{payload}, p.APIHost)
	if err != nil {
		return "", fmt.Errorf("failed to update secret: %w", err)
	}

	return "Success", nil
}

func (p *Phase) Delete(opts DeleteOptions) ([]string, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return nil, err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return nil, fmt.Errorf("no environment found with id: %s", envID)
	}

	// Decrypt seed to get env keypair
	userDataMap := appKeyResponseToMap(&userData)
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed, userDataMap)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	_, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate env key pair: %w", err)
	}

	// Fetch secrets
	secrets, err := network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.APIHost, opts.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}

	var idsToDelete []string
	var keysNotFound []string

	for _, key := range opts.KeysToDelete {
		found := false
		for _, secret := range secrets {
			if opts.Path != "" {
				secretPath, _ := secret["path"].(string)
				if secretPath != opts.Path {
					continue
				}
			}
			encKey, _ := secret["key"].(string)
			dk, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
			if err != nil {
				continue
			}
			if dk == key {
				secretID, _ := secret["id"].(string)
				idsToDelete = append(idsToDelete, secretID)
				found = true
				break
			}
		}
		if !found {
			keysNotFound = append(keysNotFound, key)
		}
	}

	if len(idsToDelete) > 0 {
		if err := network.DeletePhaseSecrets(p.TokenType, p.AppToken, envID, idsToDelete, p.APIHost); err != nil {
			return nil, fmt.Errorf("failed to delete secrets: %w", err)
		}
	}

	return keysNotFound, nil
}

// Helper functions

func appKeyResponseToMap(resp *misc.AppKeyResponse) map[string]interface{} {
	data, _ := json.Marshal(resp)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

func extractStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func getBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.ToLower(b) == "true"
	default:
		return false
	}
}
