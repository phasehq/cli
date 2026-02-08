package phase

import (
	"fmt"
	"regexp"
	"strings"
)

var secretRefRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// secretsCache keyed by "app|env|path" -> key -> value
var secretsCache = map[string]map[string]string{}

func cacheKey(app, env, path string) string {
	path = normalizePath(path)
	return fmt.Sprintf("%s|%s|%s", app, env, path)
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func primeCacheFromList(secrets []SecretResult, fallbackAppName string) {
	for _, s := range secrets {
		app := s.Application
		if app == "" {
			app = fallbackAppName
		}
		if app == "" || s.Environment == "" || s.Key == "" {
			continue
		}
		ck := cacheKey(app, s.Environment, s.Path)
		if _, ok := secretsCache[ck]; !ok {
			secretsCache[ck] = map[string]string{}
		}
		secretsCache[ck][s.Key] = s.Value
	}
}

func ensureCached(p *Phase, appName, envName, path string) {
	ck := cacheKey(appName, envName, path)
	if _, ok := secretsCache[ck]; ok {
		return
	}
	fetched, err := p.Get(GetOptions{
		EnvName: envName,
		AppName: appName,
		Path:    normalizePath(path),
	})
	if err != nil {
		return
	}
	bucket := map[string]string{}
	for _, s := range fetched {
		bucket[s.Key] = s.Value
	}
	secretsCache[ck] = bucket
}

func getFromCache(appName, envName, path, keyName string) (string, bool) {
	ck := cacheKey(appName, envName, path)
	bucket, ok := secretsCache[ck]
	if !ok {
		return "", false
	}
	val, ok := bucket[keyName]
	return val, ok
}

func splitPathAndKey(ref string) (string, string) {
	lastSlash := strings.LastIndex(ref, "/")
	if lastSlash != -1 {
		path := ref[:lastSlash]
		key := ref[lastSlash+1:]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return path, key
	}
	return "/", ref
}

func parseReferenceContext(ref, currentApp, currentEnv string) (appName, envName, path, keyName string, err error) {
	appName = currentApp
	envName = currentEnv
	refBody := ref

	isCrossApp := false
	if strings.Contains(refBody, "::") {
		isCrossApp = true
		parts := strings.SplitN(refBody, "::", 2)
		appName = parts[0]
		refBody = parts[1]
	}

	if strings.Contains(refBody, ".") {
		parts := strings.SplitN(refBody, ".", 2)
		envName = parts[0]
		refBody = parts[1]
		if isCrossApp && envName == "" {
			return "", "", "", "", fmt.Errorf("invalid reference '%s': cross-app references must specify an environment", ref)
		}
	} else if isCrossApp {
		return "", "", "", "", fmt.Errorf("invalid reference '%s': cross-app references must specify an environment", ref)
	}

	path, keyName = splitPathAndKey(refBody)
	return
}

// ResolveAllSecrets resolves all ${...} references in a value string.
func ResolveAllSecrets(value string, allSecrets []SecretResult, p *Phase, currentApp, currentEnv string) string {
	return resolveAllSecretsInternal(value, allSecrets, p, currentApp, currentEnv, nil)
}

func resolveAllSecretsInternal(value string, allSecrets []SecretResult, p *Phase, currentApp, currentEnv string, visited map[string]bool) string {
	if visited == nil {
		visited = map[string]bool{}
	}

	// Build in-memory lookup: env -> path -> key -> value
	secretsDict := map[string]map[string]map[string]string{}
	primeCacheFromList(allSecrets, currentApp)
	for _, s := range allSecrets {
		if _, ok := secretsDict[s.Environment]; !ok {
			secretsDict[s.Environment] = map[string]map[string]string{}
		}
		if _, ok := secretsDict[s.Environment][s.Path]; !ok {
			secretsDict[s.Environment][s.Path] = map[string]string{}
		}
		secretsDict[s.Environment][s.Path][s.Key] = s.Value
	}

	refs := secretRefRegex.FindAllStringSubmatch(value, -1)
	if len(refs) == 0 {
		return value
	}

	// Prefetch caches
	seen := map[string]bool{}
	for _, match := range refs {
		ref := match[1]
		app, env, path, _, err := parseReferenceContext(ref, currentApp, currentEnv)
		if err != nil {
			continue
		}
		combo := fmt.Sprintf("%s|%s|%s", app, env, path)
		if !seen[combo] {
			seen[combo] = true
			ensureCached(p, app, env, path)
		}
	}

	resolved := value
	for _, match := range refs {
		ref := match[1]
		fullRef := match[0]

		app, env, path, keyName, err := parseReferenceContext(ref, currentApp, currentEnv)
		if err != nil {
			continue
		}

		canonical := fmt.Sprintf("%s|%s|%s|%s", app, env, path, keyName)
		if visited[canonical] {
			continue
		}
		visited[canonical] = true

		// Try in-memory dict first (same app only)
		resolvedVal := ""
		found := false
		if app == currentApp {
			resolvedVal, found = lookupInMemory(secretsDict, env, path, keyName, currentEnv)
		}

		// Try cache
		if !found {
			resolvedVal, found = getFromCache(app, env, path, keyName)
		}

		if !found {
			// Leave placeholder unresolved
			continue
		}

		// Recursively resolve if the resolved value itself contains references
		if secretRefRegex.MatchString(resolvedVal) {
			resolvedVal = resolveAllSecretsInternal(resolvedVal, allSecrets, p, app, env, visited)
		}

		resolved = strings.ReplaceAll(resolved, fullRef, resolvedVal)
	}

	return resolved
}

func lookupInMemory(secretsDict map[string]map[string]map[string]string, envName, path, keyName, currentEnv string) (string, bool) {
	envKey := findEnvKeyCaseInsensitive(secretsDict, envName)
	if envKey == "" {
		return "", false
	}
	if pathBucket, ok := secretsDict[envKey][path]; ok {
		if val, ok := pathBucket[keyName]; ok {
			return val, true
		}
	}
	// Fallback: try root path for current env
	if path == "/" && strings.EqualFold(envName, currentEnv) {
		if pathBucket, ok := secretsDict[envKey]["/"]; ok {
			if val, ok := pathBucket[keyName]; ok {
				return val, true
			}
		}
	}
	return "", false
}

func findEnvKeyCaseInsensitive(secretsDict map[string]map[string]map[string]string, envName string) string {
	// Exact match
	if _, ok := secretsDict[envName]; ok {
		return envName
	}
	// Case-insensitive exact match
	for k := range secretsDict {
		if strings.EqualFold(k, envName) {
			return k
		}
	}
	// Partial match
	envLower := strings.ToLower(envName)
	var partials []string
	for k := range secretsDict {
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, envLower) || strings.Contains(envLower, kLower) {
			partials = append(partials, k)
		}
	}
	if len(partials) > 0 {
		shortest := partials[0]
		for _, p := range partials[1:] {
			if len(p) < len(shortest) {
				shortest = p
			}
		}
		return shortest
	}
	return ""
}
