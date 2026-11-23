package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ManifestHost = "phase.invalid"
	ManifestPath = "/.well-known/agents"
	ManifestURL  = "http://" + ManifestHost + ManifestPath
	ControlURL   = "http://" + ManifestHost
	// ControlIntentHeader, set to "1", marks a control call the CLI itself
	// makes. The routes that end or change the session require it, so a
	// client that follows an upstream's redirect to ControlURL cannot reach them.
	ControlIntentHeader = "X-Phase-Control"

	maxCABundleBytes       = 16 << 20
	maxMergedCABundleBytes = 32 << 20
	maxCABundleSources     = 32
)

type EnvironmentOptions struct {
	Base             []string
	ProxyURL         string
	CABundlePath     string
	CABundleComplete bool
	ConfigEnv        map[string]string
	AgentEnv         map[string]string
	AdapterEnv       map[string]string
	// CredentialEnvironment is the union of the session's Connections'
	// credentialEnvironment: the variables their providers' own tools read
	// credentials from. configEnv may not supply them, and they are exported
	// as ReservedEnvironmentKey for phase run.
	CredentialEnvironment []string
	// ScopedTrustKeys are the provider-scoped trust variables to point at the
	// Phase bundle (see ScopedTrustEnvironmentKeys).
	ScopedTrustKeys []string
	// EnvironmentBindings is the authoritative, resolved provider binding
	// metadata supplied by the v1 Console contract.
	EnvironmentBindings []EnvironmentBinding
	// ProxyRequiredHosts contains the trusted connection host patterns which
	// must never survive in NO_PROXY/no_proxy. The reserved manifest origin is
	// protected automatically.
	ProxyRequiredHosts []string
}

// EnvironmentBinding is the small, resolved portion of the Console binding
// contract needed by the process compiler. Values remain in ConfigEnv and
// AgentEnv; metadata tells the CLI which inherited names to remove.
type EnvironmentBinding struct {
	Name        string
	Action      string
	Source      string
	SourceField string
}

// PreparedCABundle is a process-local, certificate-only trust bundle. Complete
// means the bundle contains a normal base root set in addition to Phase's CA,
// and is therefore safe for variables which replace a client's default roots.
type PreparedCABundle struct {
	BundlePath string
	Complete   bool
}

// ProcessEnvironmentPlan is safe to expose through the authenticated Agent
// manifest. Set contains only configuration and decoy values; Unset identifies
// inherited credentials that would compete with an injected provider family.
type ProcessEnvironmentPlan struct {
	Set   map[string]string `json:"set"`
	Unset []string          `json:"unset"`
}

func (p ProcessEnvironmentPlan) String() string {
	return fmt.Sprintf("ProcessEnvironmentPlan{Set:[REDACTED] Unset:%v}", p.Unset)
}

func (p ProcessEnvironmentPlan) GoString() string { return p.String() }

func (p ProcessEnvironmentPlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

var protectedEnvironmentKeys = map[string]struct{}{
	"PHASE_SERVICE_TOKEN":              {},
	"PHASE_AGENT_TOKEN":                {},
	"PHASE_AI_ENABLED":                 {},
	"PHASE_AI_CA_BUNDLE":               {},
	"PHASE_AI_CONTROL_URL":             {},
	ReservedEnvironmentKey:             {},
	"HTTP_PROXY":                       {},
	"HTTPS_PROXY":                      {},
	"ALL_PROXY":                        {},
	"SSL_CERT_FILE":                    {},
	"SSL_CERT_DIR":                     {},
	"REQUESTS_CA_BUNDLE":               {},
	"CURL_CA_BUNDLE":                   {},
	"NODE_EXTRA_CA_CERTS":              {},
	"AWS_CA_BUNDLE":                    {},
	"GIT_SSL_CAINFO":                   {},
	"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH": {},
	"NIX_SSL_CERT_FILE":                {},
	"PIP_CERT":                         {},
	"DENO_CERT":                        {},
	"PGSSLROOTCERT":                    {},
	"NO_PROXY":                         {},
	"JAVA_TOOL_OPTIONS":                {},
}

// ReservedEnvironmentKey lists, comma-separated, every variable the session
// sets or removes for its processes and the credential variables of the
// session's providers. phase run runs as its own process without the session,
// and reads the names it must not let an app secret replace here.
const ReservedEnvironmentKey = "PHASE_AI_RESERVED_ENV"

// phaseCredentialEnvironmentKeys are Phase's own credential variables. Every
// provider's come with its Connections (CredentialEnvironment).
var phaseCredentialEnvironmentKeys = []string{"PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN"}

// phaseSessionConnectionKeys point the CLI at a Console; inside a session an
// app secret must not send phase itself elsewhere.
var phaseSessionConnectionKeys = []string{"PHASE_HOST", "PHASE_VERIFY_SSL"}

var alwaysUnsetEnvironmentKeys = []string{"PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN"}

var customCABundleEnvironmentKeys = map[string]struct{}{
	"SSL_CERT_FILE": {}, "REQUESTS_CA_BUNDLE": {}, "CURL_CA_BUNDLE": {}, "NODE_EXTRA_CA_CERTS": {},
	"AWS_CA_BUNDLE": {}, "GIT_SSL_CAINFO": {}, "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH": {},
	"NIX_SSL_CERT_FILE": {}, "PIP_CERT": {}, "DENO_CERT": {}, "PGSSLROOTCERT": {},
}

// RuntimeControlEnvironmentKey reports whether key only has meaning while the
// Phase proxy process that issued it is reachable: proxy routing, the Phase
// runtime markers, and trust-store overrides for the Phase CA. Decoys, adapter
// endpoints, and configEnv values are not control keys; a harness may keep them
// exported after the proxy exits so ambient provider credentials are never used
// in place of a Phase-managed Connection.
func RuntimeControlEnvironmentKey(key string) bool {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "PHASE_AI_ENABLED", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		return true
	}
	return TrustEnvironmentKey(key)
}

// ReservedRunEnvironmentKey reports whether a variable name belongs to a Phase
// AI session: proxy routing, trust settings, the Phase runtime and token
// variables, and every credential variable of a provider the session's
// Connections cover (sessionReserved, read from ReservedEnvironmentKey).
// phase run inside a session never lets an app secret replace one of them, or
// a secret could take the place of a decoy or route traffic around the proxy.
// Names are compared case-insensitively, as proxy and CA variables are read in
// either case.
func ReservedRunEnvironmentKey(key string, sessionReserved []string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if strings.HasPrefix(key, "PHASE_AI_") || strings.HasPrefix(key, "PHASE_AGENT_") {
		return true
	}
	if _, ok := protectedEnvironmentKeys[key]; ok {
		return true
	}
	return containsEnvironmentKey(phaseCredentialEnvironmentKeys, key) || containsEnvironmentKey(phaseSessionConnectionKeys, key) ||
		containsEnvironmentKey(sessionReserved, key)
}

// ReservedNamesHold reports whether a process started with current already
// reserves every name next does, so a refresh that only drops names (a removed
// Connection) does not need the session restarted.
func ReservedNamesHold(current, next string) bool {
	held := SplitReservedEnvironment(current)
	for _, name := range SplitReservedEnvironment(next) {
		if !containsEnvironmentKey(held, name) {
			return false
		}
	}
	return true
}

// PlanCarriesReservedNames reports whether a plan that enables Phase AI also
// carries ReservedEnvironmentKey, which phase run needs inside the session.
func PlanCarriesReservedNames(plan ProcessEnvironmentPlan) bool {
	if plan.Set["PHASE_AI_ENABLED"] != "1" {
		return true
	}
	_, present := plan.Set[ReservedEnvironmentKey]
	return present
}

// SplitReservedEnvironment reads the value of ReservedEnvironmentKey.
func SplitReservedEnvironment(value string) []string {
	var names []string
	for _, name := range strings.Split(value, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// TrustEnvironmentKey reports whether key points clients at CA material.
func TrustEnvironmentKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	_, ok := customCABundleEnvironmentKeys[key]
	return ok || key == "PHASE_AI_CA_BUNDLE" || key == "JAVA_TOOL_OPTIONS"
}

// ScopedTrustEnvironmentKeys names the provider-scoped trust variables of the
// clients whose traffic the Connection's own protocol handling covers: the AWS
// SDKs for a SigV4 Connection, libpq for the PostgreSQL adapter. They describe
// client tools, not providers, so they stay in the CLI.
func ScopedTrustEnvironmentKeys(injectionAction string) []string {
	switch strings.ToLower(strings.TrimSpace(injectionAction)) {
	case "aws_sigv4":
		return []string{"AWS_CA_BUNDLE"}
	case "pg_handshake":
		return []string{"PGSSLROOTCERT"}
	default:
		return nil
	}
}

type caBundleSource struct {
	path     string
	required bool
	complete bool
}

// PrepareProcessCABundle merges every available system and inherited public
// CA bundle with Phase's CA. Sources are never edited, duplicate certificates
// are removed, and a source containing private-key material is rejected.
func PrepareProcessCABundle(baseBundlePath string, environment []string, scopedTrustKeys []string) (PreparedCABundle, func(), error) {
	return prepareProcessCABundle(baseBundlePath, environment, scopedTrustKeys, runtime.GOOS, nil)
}

// runtimeBundleMaxAge is how long a published bundle is kept after the last
// session that asked for it started. Each start marks its bundle as used and
// sessions are far shorter than this, so a bundle this old serves nobody.
const runtimeBundleMaxAge = 30 * 24 * time.Hour

// runtimeBundleName matches the bundles PrepareStableProcessCABundle publishes.
var runtimeBundleName = regexp.MustCompile(`^runtime-ca-bundle-[0-9a-f]{32}\.pem$`)

// PrepareStableProcessCABundle prepares the same certificate-only merged root
// set as PrepareProcessCABundle, then atomically publishes it beside the
// installation CA, in a file named by a hash of its contents. phase ai run,
// phase ai exec and the hook daemons therefore expose a PHASE_AI_CA_BUNDLE
// path that holds for the full proxy lifetime instead of handing clients an
// ephemeral /tmp file, and a session that inherits other CAs gets a file of
// its own instead of replacing this one. The published file contains only
// public certificates and intentionally remains available after the proxy
// exits; one no session has asked for in runtimeBundleMaxAge is removed.
func PrepareStableProcessCABundle(baseBundlePath string, environment []string, scopedTrustKeys []string) (PreparedCABundle, error) {
	directory := filepath.Dir(baseBundlePath)
	// Ensure publishes the base bundle under the same lock. Holding it from
	// read to publish means a proxy that read an older base bundle cannot
	// overwrite a newer one, which in memory-only mode would drop another
	// live proxy's CA from the file its children trust.
	unlock, err := lockCAFile(filepath.Join(directory, "ca.lock"))
	if err != nil {
		return PreparedCABundle{}, fmt.Errorf("lock proxy CA: %w", err)
	}
	defer unlock()
	prepared, cleanup, err := PrepareProcessCABundle(baseBundlePath, environment, scopedTrustKeys)
	if err != nil {
		return PreparedCABundle{}, err
	}
	defer cleanup()

	bundle, err := os.ReadFile(prepared.BundlePath)
	if err != nil {
		return PreparedCABundle{}, fmt.Errorf("read prepared Phase AI CA bundle: %w", err)
	}
	if _, err := readBoundedPublicCertificates(prepared.BundlePath); err != nil {
		return PreparedCABundle{}, fmt.Errorf("validate prepared Phase AI CA bundle: %w", err)
	}
	digest := sha256.Sum256(bundle)
	stable := PreparedCABundle{
		BundlePath: filepath.Join(directory, "runtime-ca-bundle-"+hex.EncodeToString(digest[:16])+".pem"),
		Complete:   prepared.Complete,
	}
	now := time.Now()
	if err := writeStableTrustFile(stable.BundlePath, bundle, runtime.GOOS, now); err != nil {
		return PreparedCABundle{}, fmt.Errorf("publish stable Phase AI CA bundle: %w", err)
	}
	removeStaleRuntimeBundles(directory, stable.BundlePath, now)
	return stable, nil
}

func writeStableTrustFile(destination string, payload []byte, goos string, now time.Time) error {
	if info, err := os.Lstat(destination); err == nil && info.Mode().IsRegular() {
		if existing, readErr := os.ReadFile(destination); readErr == nil && bytes.Equal(existing, payload) {
			// The file's age is what removes it, so reusing it marks it as used.
			if err := os.Chtimes(destination, now, now); err != nil {
				return err
			}
			return os.Chmod(destination, 0o600)
		}
	}
	if err := writeFileAtomic0600(destination, payload); err == nil {
		return nil
	} else if goos != "windows" {
		return err
	}
	// Windows does not consistently allow Rename to replace an existing file.
	// The directory is owner-only and the payload is public trust material, so
	// remove-and-republish is the bounded compatibility fallback.
	if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return writeFileAtomic0600(destination, payload)
}

// removeStaleRuntimeBundles removes the published bundles that no session has
// asked for in runtimeBundleMaxAge, so they do not pile up as trust sets
// change. A live session's bundle is never that old. Called with ca.lock held;
// a file that cannot be removed is left for the next start.
func removeStaleRuntimeBundles(directory, current string, now time.Time) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if path == current || !entry.Type().IsRegular() || !runtimeBundleName.MatchString(entry.Name()) {
			continue
		}
		if info, err := entry.Info(); err == nil && now.Sub(info.ModTime()) > runtimeBundleMaxAge {
			_ = os.Remove(path)
		}
	}
}

func prepareProcessCABundle(baseBundlePath string, environment []string, scopedTrustKeys []string, goos string, systemPaths []string) (PreparedCABundle, func(), error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	if systemPaths == nil {
		systemPaths = systemCABundlePaths(goos, environment)
	}
	sources := []caBundleSource{{path: baseBundlePath, required: true}}
	seenPaths := map[string]struct{}{filepath.Clean(baseBundlePath): {}}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if _, relevant := customCABundleEnvironmentKeys[upper]; !relevant {
			continue
		}
		if (upper == "AWS_CA_BUNDLE" || upper == "PGSSLROOTCERT") && !containsEnvironmentKey(scopedTrustKeys, upper) {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		clean := filepath.Clean(value)
		if _, duplicate := seenPaths[clean]; duplicate {
			continue
		}
		seenPaths[clean] = struct{}{}
		// NODE_EXTRA_CA_CERTS and provider-specific roots are additive or
		// scoped; they must be retained but cannot prove a globally complete
		// public root set.
		complete := upper != "NODE_EXTRA_CA_CERTS" && upper != "AWS_CA_BUNDLE" && upper != "PGSSLROOTCERT"
		sources = append(sources, caBundleSource{path: value, required: true, complete: complete})
	}
	for _, candidate := range systemPaths {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		clean := filepath.Clean(candidate)
		if _, duplicate := seenPaths[clean]; duplicate {
			continue
		}
		seenPaths[clean] = struct{}{}
		sources = append(sources, caBundleSource{path: candidate, complete: true})
	}
	if len(sources) > maxCABundleSources {
		return PreparedCABundle{}, func() {}, fmt.Errorf("too many CA bundle sources: %d exceeds %d", len(sources), maxCABundleSources)
	}

	certificates := make([][]byte, 0)
	seenCertificates := make(map[string]struct{})
	mergedBytes := 0
	complete := false
	for index, source := range sources {
		blocks, err := readBoundedPublicCertificates(source.path)
		if err != nil {
			if !source.required && errors.Is(err, os.ErrNotExist) {
				continue
			}
			label := "CA bundle"
			if index == 0 {
				label = "Phase AI CA bundle"
			}
			return PreparedCABundle{}, func() {}, fmt.Errorf("read %s %s: %w", label, source.path, err)
		}
		if index == 0 && len(blocks) > 1 {
			// CAStore writes this path from a discovered system bundle. Retain
			// that completeness even if the source disappears between enable
			// and run.
			complete = true
		}
		if source.complete {
			complete = true
		}
		for _, certificate := range blocks {
			fingerprint := string(certificate)
			if _, duplicate := seenCertificates[fingerprint]; duplicate {
				continue
			}
			seenCertificates[fingerprint] = struct{}{}
			mergedBytes += len(certificate) + 64
			if mergedBytes > maxMergedCABundleBytes {
				return PreparedCABundle{}, func() {}, fmt.Errorf("merged CA bundle exceeds %d MiB", maxMergedCABundleBytes>>20)
			}
			certificates = append(certificates, certificate)
		}
	}
	if len(certificates) == 0 {
		return PreparedCABundle{}, func() {}, errors.New("Phase AI CA bundle contains no public certificates")
	}
	merged := encodeCertificateBlocks(certificates)
	bundlePath, err := writeTemporaryTrustFile("phase-ai-ca-bundle-*.pem", merged)
	if err != nil {
		return PreparedCABundle{}, func() {}, err
	}
	cleanupPaths := []string{bundlePath}
	prepared := PreparedCABundle{BundlePath: bundlePath, Complete: complete}
	cleanup := func() {
		for _, path := range cleanupPaths {
			_ = os.Remove(path)
		}
	}
	return prepared, cleanup, nil
}

func readBoundedPublicCertificates(path string) ([][]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxCABundleBytes {
		return nil, fmt.Errorf("CA bundle must be a non-empty regular file no larger than %d MiB", maxCABundleBytes>>20)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0)
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			return nil, errors.New("CA bundle must not contain private-key material")
		}
		if block.Type == "CERTIFICATE" && len(block.Bytes) > 0 {
			result = append(result, append([]byte(nil), block.Bytes...))
		}
	}
	if len(result) == 0 {
		return nil, errors.New("CA bundle contains no public certificates")
	}
	return result, nil
}

func encodeCertificateBlocks(certificates [][]byte) []byte {
	var result []byte
	for _, certificate := range certificates {
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	return result
}

func writeTemporaryTrustFile(pattern string, payload []byte) (string, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create process-local trust file: %w", err)
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("protect process-local trust file: %w", err)
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write process-local trust file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close process-local trust file: %w", err)
	}
	return path, nil
}

func systemCABundlePaths(goos string, environment []string) []string {
	values := make(map[string]string)
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(key)] = strings.TrimSpace(value)
		}
	}
	switch goos {
	case "darwin":
		return []string{
			"/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem",
			"/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem",
		}
	case "windows":
		var result []string
		for _, root := range []string{values["PROGRAMFILES"], values["PROGRAMFILES(X86)"]} {
			if root == "" {
				continue
			}
			result = append(result,
				filepath.Join(root, "Git", "mingw64", "etc", "ssl", "certs", "ca-bundle.crt"),
				filepath.Join(root, "Git", "usr", "ssl", "certs", "ca-bundle.crt"),
			)
		}
		return result
	default:
		return []string{
			"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/ca-certificates/extracted/tls-ca-bundle.pem",
		}
	}
}

// PlanResolvedProcessEnvironment compiles provider-owned values and explicit
// cleanup without adding CLI-local proxy or CA bindings. It is used for the
// authenticated discovery manifest; run and serve use CompileProcessEnvironment
// for their complete launch environment.
func PlanResolvedProcessEnvironment(configEnv, agentEnv map[string]string, bindings []EnvironmentBinding, credentialEnvironment []string) (ProcessEnvironmentPlan, error) {
	return planProcessEnvironment(configEnv, agentEnv, bindings, credentialEnvironment)
}

func planProcessEnvironment(configEnv, agentEnv map[string]string, bindings []EnvironmentBinding, credentialEnvironment []string) (ProcessEnvironmentPlan, error) {
	set := make(map[string]string)
	if err := mergeRuntimeEnvironment(set, configEnv, "configEnv", credentialEnvironment); err != nil {
		return ProcessEnvironmentPlan{}, err
	}
	if err := mergeRuntimeEnvironment(set, agentEnv, "agentEnv", credentialEnvironment); err != nil {
		return ProcessEnvironmentPlan{}, err
	}

	// Competing ambient credentials are removed only when the backend actually
	// supplied a decoy for that provider. A connection's service type alone is
	// not permission to erase the user's ambient provider selection.
	unsetSet := make(map[string]struct{})
	for _, key := range alwaysUnsetEnvironmentKeys {
		unsetSet[key] = struct{}{}
	}
	seenBindings := make(map[string]string, len(bindings))
	declaredAgentSet := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !ValidShellEnvironmentKey(binding.Name) || binding.Name != strings.ToUpper(binding.Name) {
			return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding contains an invalid name")
		}
		canonical := strings.ToUpper(binding.Name)
		if _, exists := seenBindings[canonical]; exists {
			return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s is duplicated", binding.Name)
		}
		seenBindings[canonical] = binding.Action
		switch binding.Action {
		case "set":
			switch binding.Source {
			case "identifier", "decoy":
				if strings.TrimSpace(binding.SourceField) == "" {
					return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has no source field", binding.Name)
				}
				if _, present := agentEnv[binding.Name]; !present {
					return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has no value in agentEnv", binding.Name)
				}
				declaredAgentSet[binding.Name] = struct{}{}
			case "connection_config":
				if strings.TrimSpace(binding.SourceField) == "" {
					return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has no source field", binding.Name)
				}
				if _, present := configEnv[binding.Name]; !present {
					return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has no value in configEnv", binding.Name)
				}
			case "proxy", "ca":
				return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s uses an unresolved CLI-local source", binding.Name)
			default:
				return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has unsupported source %q", binding.Name, binding.Source)
			}
		case "unset":
			if binding.Source != "runtime" || strings.TrimSpace(binding.SourceField) == "" {
				return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has invalid runtime cleanup provenance", binding.Name)
			}
			unsetSet[canonical] = struct{}{}
		default:
			return ProcessEnvironmentPlan{}, fmt.Errorf("environment binding %s has unsupported action %q", binding.Name, binding.Action)
		}
	}
	for key := range agentEnv {
		if _, declared := declaredAgentSet[key]; !declared {
			return ProcessEnvironmentPlan{}, fmt.Errorf("agentEnv key %s has no environment binding", key)
		}
	}
	for key := range set {
		canonical := strings.ToUpper(key)
		if _, collision := unsetSet[canonical]; !collision {
			continue
		}
		return ProcessEnvironmentPlan{}, fmt.Errorf("environment key %s cannot be both set and unset", key)
	}
	unset := make([]string, 0, len(unsetSet))
	for key := range unsetSet {
		unset = append(unset, key)
	}
	sort.Strings(unset)
	return ProcessEnvironmentPlan{Set: set, Unset: unset}, nil
}

// CompileProcessEnvironment produces the complete Phase-owned process delta.
// It contains backend configuration/decoys, adapter variables, proxy aliases,
// CA compatibility variables, and explicit removals. It never copies unrelated
// inherited values into Set, so it is safe to show through the authenticated
// manifest.
func CompileProcessEnvironment(options EnvironmentOptions) (ProcessEnvironmentPlan, error) {
	proxyURL, err := validateProxyEnvironmentOptions(options)
	if err != nil {
		return ProcessEnvironmentPlan{}, err
	}
	plan, err := planProcessEnvironment(
		options.ConfigEnv,
		options.AgentEnv,
		options.EnvironmentBindings,
		options.CredentialEnvironment,
	)
	if err != nil {
		return ProcessEnvironmentPlan{}, err
	}

	if err := mergeAdapterEnvironment(plan.Set, options.AdapterEnv); err != nil {
		return ProcessEnvironmentPlan{}, err
	}
	proxy := proxyURL.String()
	controls := map[string]string{
		"PHASE_AI_ENABLED":    "1",
		"PHASE_AI_CA_BUNDLE":  options.CABundlePath,
		"HTTP_PROXY":          proxy,
		"HTTPS_PROXY":         proxy,
		"http_proxy":          proxy,
		"https_proxy":         proxy,
		"NODE_EXTRA_CA_CERTS": options.CABundlePath,
		// Always set, so a value inherited from an outer session never stands;
		// its value is filled in once the plan is complete.
		ReservedEnvironmentKey: "",
	}
	noProxy := sanitizedNoProxy(options.Base, options.ProxyRequiredHosts)
	controls["NO_PROXY"] = noProxy
	controls["no_proxy"] = noProxy
	if options.CABundleComplete {
		for _, key := range []string{
			"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
			"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "NIX_SSL_CERT_FILE", "PIP_CERT", "DENO_CERT",
		} {
			controls[key] = options.CABundlePath
		}
	}
	// Provider-scoped clients must trust the Phase MITM on their very first
	// request. Unlike global replacement roots, these variables are safe to
	// point at a Phase-only bundle because the corresponding traffic is bound
	// to the Phase proxy.
	for _, key := range options.ScopedTrustKeys {
		if upper := strings.ToUpper(key); upper == "AWS_CA_BUNDLE" || upper == "PGSSLROOTCERT" {
			controls[upper] = options.CABundlePath
		}
	}
	for key, value := range controls {
		if err := mergeOwnedEnvironment(plan.Set, key, value, "Phase runtime"); err != nil {
			return ProcessEnvironmentPlan{}, err
		}
	}
	for key, value := range plan.Set {
		if err := validateEnvironmentValue(value); err != nil {
			return ProcessEnvironmentPlan{}, fmt.Errorf("environment key %s: %w", key, err)
		}
	}
	plan.Unset, err = normalizeAndValidateUnsets(plan.Unset, plan.Set, explicitEnvironmentUnsets(options.EnvironmentBindings))
	if err != nil {
		return ProcessEnvironmentPlan{}, err
	}
	// phase run must not replace anything the session sets or removes, not
	// only the providers' credential variables: a decoy under another name or
	// an adapter's PGHOST is the session's too.
	reserved := append([]string(nil), options.CredentialEnvironment...)
	for key := range plan.Set {
		reserved = append(reserved, key)
	}
	reserved = append(reserved, plan.Unset...)
	plan.Set[ReservedEnvironmentKey] = reservedEnvironmentValue(reserved)
	if err := validateEnvironmentValue(plan.Set[ReservedEnvironmentKey]); err != nil {
		return ProcessEnvironmentPlan{}, fmt.Errorf("environment key %s: %w", ReservedEnvironmentKey, err)
	}
	return plan, nil
}

// ApplyProcessEnvironment applies a compiled Phase-owned delta to an inherited
// process environment without modifying the parent process or any files.
// Only the keys Phase sets or unsets must be shell identifiers.
func ApplyProcessEnvironment(base []string, plan ProcessEnvironmentPlan) ([]string, error) {
	values := make(map[string]string)
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validInheritedEnvironmentKey(key) || containsEnvironmentKey(plan.Unset, key) {
			continue
		}
		if _, phaseOwned := planValue(plan.Set, key); phaseOwned {
			continue
		}
		values[key] = value
	}
	for key, value := range plan.Set {
		for inheritedKey := range values {
			if strings.EqualFold(inheritedKey, key) && !isIntentionalCaseAlias(inheritedKey, key) {
				delete(values, inheritedKey)
			}
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

// validInheritedEnvironmentKey accepts names such as ProgramFiles(x86), but not
// the empty names Windows' hidden "=C:" entries split into.
func validInheritedEnvironmentKey(key string) bool {
	return key != "" && !strings.ContainsAny(key, "=\x00")
}

// ValidShellEnvironmentKey reports whether a key can be emitted as a POSIX
// shell assignment without interpreting any part of it as shell syntax.
func ValidShellEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for index, character := range key {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func validateProxyEnvironmentOptions(options EnvironmentOptions) (*url.URL, error) {
	proxyURL, err := url.Parse(options.ProxyURL)
	if err != nil || proxyURL.Scheme != "http" ||
		proxyURL.Host == "" || proxyURL.User == nil || proxyURL.Path != "" ||
		proxyURL.RawPath != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return nil, fmt.Errorf("invalid AI proxy URL")
	}
	capability, present := proxyURL.User.Password()
	if !ValidProxyUsername(proxyURL.User.Username()) || !present || capability == "" {
		return nil, fmt.Errorf("AI proxy URL must contain a runtime capability")
	}
	if !IsLoopbackHost(proxyURL.Hostname()) {
		return nil, fmt.Errorf("AI proxy URL must use loopback")
	}
	if options.CABundlePath == "" {
		return nil, fmt.Errorf("AI proxy CA bundle path is required")
	}
	return proxyURL, nil
}

func normalizeAndValidateUnsets(unset []string, set map[string]string, strict map[string]struct{}) ([]string, error) {
	result := make([]string, 0, len(unset))
	seen := make(map[string]struct{}, len(unset))
	for _, key := range unset {
		canonical := strings.ToUpper(key)
		if _, present := planValue(set, key); present {
			if _, explicit := strict[canonical]; explicit {
				return nil, fmt.Errorf("environment key %s cannot be both set and unset", key)
			}
			return nil, fmt.Errorf("environment key %s cannot be both set and unset", key)
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func explicitEnvironmentUnsets(bindings []EnvironmentBinding) map[string]struct{} {
	result := make(map[string]struct{}, len(bindings)+len(alwaysUnsetEnvironmentKeys))
	for _, key := range alwaysUnsetEnvironmentKeys {
		result[strings.ToUpper(key)] = struct{}{}
	}
	for _, binding := range bindings {
		if binding.Action == "unset" {
			result[strings.ToUpper(binding.Name)] = struct{}{}
		}
	}
	return result
}

func planValue(values map[string]string, target string) (string, bool) {
	for key, value := range values {
		if strings.EqualFold(key, target) {
			return value, true
		}
	}
	return "", false
}

func mergeOwnedEnvironment(destination map[string]string, key, value, owner string) error {
	if !ValidShellEnvironmentKey(key) {
		return fmt.Errorf("%s contains an invalid environment key", owner)
	}
	for existing, existingValue := range destination {
		if !strings.EqualFold(existing, key) {
			continue
		}
		if existingValue == value {
			if existing == key {
				return nil
			}
			if isIntentionalCaseAlias(existing, key) {
				destination[key] = value
				return nil
			}
		}
		return fmt.Errorf("%s conflicts with environment key %s", owner, key)
	}
	destination[key] = value
	return nil
}

func isIntentionalCaseAlias(left, right string) bool {
	if left == right || !strings.EqualFold(left, right) {
		return false
	}
	switch strings.ToUpper(left) {
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
		return (left == strings.ToUpper(left) && right == strings.ToLower(right)) ||
			(right == strings.ToUpper(right) && left == strings.ToLower(left))
	default:
		return false
	}
}

func validateEnvironmentValue(value string) error {
	if strings.IndexByte(value, 0) >= 0 || strings.ContainsAny(value, "\r\n") {
		return errors.New("environment values must be single-line and contain no NUL bytes")
	}
	if len(value) > 64<<10 {
		return errors.New("environment value exceeds 64 KiB")
	}
	return nil
}

func sanitizedNoProxy(environment []string, proxyRequiredHosts []string) string {
	candidates := []string{"127.0.0.1", "localhost", "::1"}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		value := inheritedExactEnvironmentValue(environment, name)
		if value != "" {
			candidates = append(candidates, strings.Split(value, ",")...)
		}
	}
	result := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if len(result) >= 256 {
			break
		}
		candidate = strings.TrimSpace(candidate)
		if !validNoProxyEntry(candidate) ||
			noProxyEntryOverlapsHost(candidate, ManifestHost) {
			continue
		}
		blocked := false
		for _, required := range proxyRequiredHosts {
			if noProxyEntryOverlapsHost(candidate, required) {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		canonical := strings.ToLower(candidate)
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		if len(strings.Join(append(result, candidate), ",")) > 8<<10 {
			break
		}
		result = append(result, candidate)
	}
	return strings.Join(result, ",")
}

func validNoProxyEntry(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "*") || strings.Contains(value, "://") ||
		strings.Contains(value, "@") || strings.ContainsAny(value, " \t\r\n\x00") {
		return false
	}
	host := value
	if strings.Contains(value, "/") {
		_, _, err := net.ParseCIDR(value)
		return err == nil
	}
	if strings.HasPrefix(value, "[") {
		closing := strings.IndexByte(value, ']')
		if closing < 0 {
			return false
		}
		host = value[1:closing]
		if suffix := value[closing+1:]; suffix != "" {
			if !validNoProxyPort(strings.TrimPrefix(suffix, ":")) || !strings.HasPrefix(suffix, ":") {
				return false
			}
		}
		return net.ParseIP(host) != nil
	}
	if strings.Count(value, ":") == 1 {
		var rawPort string
		var err error
		host, rawPort, err = net.SplitHostPort(value)
		if err != nil || !validNoProxyPort(rawPort) {
			return false
		}
	} else if strings.Count(value, ":") > 1 {
		return net.ParseIP(value) != nil
	}
	host = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validNoProxyPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}

func inheritedExactEnvironmentValue(environment []string, target string) string {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == target {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func noProxyEntryOverlapsHost(entry, required string) bool {
	entryHost := normalizeNoProxyHost(entry)
	requiredHost := normalizeNoProxyHost(required)
	if entryHost == "" || requiredHost == "" {
		return false
	}
	if network, err := parseNoProxyCIDR(entryHost); err == nil && network != nil {
		return net.ParseIP(requiredHost) != nil && network.Contains(net.ParseIP(requiredHost))
	}
	entryIP, requiredIP := net.ParseIP(entryHost), net.ParseIP(requiredHost)
	if entryIP != nil || requiredIP != nil {
		return entryIP != nil && requiredIP != nil && entryIP.Equal(requiredIP)
	}
	return entryHost == requiredHost || strings.HasSuffix(entryHost, "."+requiredHost) || strings.HasSuffix(requiredHost, "."+entryHost)
}

func parseNoProxyCIDR(value string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(value)
	return network, err
}

func normalizeNoProxyHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if strings.HasPrefix(value, "[") {
		if host, _, err := net.SplitHostPort(value); err == nil {
			return strings.Trim(host, "[]")
		}
		return strings.Trim(value, "[]")
	}
	if strings.Count(value, ":") == 1 {
		if host, _, err := net.SplitHostPort(value); err == nil {
			return host
		}
	}
	return value
}

// reservedEnvironmentValue is the sorted, de-duplicated list of variable
// names for ReservedEnvironmentKey.
func reservedEnvironmentValue(names []string) string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		upper := strings.ToUpper(strings.TrimSpace(name))
		if _, duplicate := seen[upper]; duplicate || !ValidShellEnvironmentKey(upper) {
			continue
		}
		seen[upper] = struct{}{}
		result = append(result, upper)
	}
	sort.Strings(result)
	return strings.Join(result, ",")
}

func containsEnvironmentKey(keys []string, target string) bool {
	for _, key := range keys {
		if strings.EqualFold(key, target) {
			return true
		}
	}
	return false
}

var adapterEnvironmentKeys = map[string]struct{}{
	"PGHOST": {}, "PGPORT": {}, "PGPASSWORD": {}, "PGSSLMODE": {}, "PGSSLROOTCERT": {},
}

func mergeAdapterEnvironment(destination, source map[string]string) error {
	for key, value := range source {
		upper := strings.ToUpper(key)
		if _, allowed := adapterEnvironmentKeys[upper]; !allowed || key == "" || strings.Contains(key, "=") {
			return fmt.Errorf("adapterEnv contains unsupported key %s", key)
		}
		for existing, existingValue := range destination {
			if strings.EqualFold(existing, key) {
				if existingValue != value || existing != key {
					return fmt.Errorf("adapterEnv conflicts with environment key %s", key)
				}
				continue
			}
		}
		destination[key] = value
	}
	return nil
}

// IsLoopbackHost reports whether host, a URL hostname, names this machine:
// localhost (any case, optional trailing dot) or a loopback IP.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func mergeRuntimeEnvironment(destination, source map[string]string, label string, credentialEnvironment []string) error {
	for key, value := range source {
		if !ValidShellEnvironmentKey(key) {
			return fmt.Errorf("%s contains an invalid environment key", label)
		}
		upper := strings.ToUpper(key)
		if _, protected := protectedEnvironmentKeys[upper]; protected || strings.HasPrefix(upper, "PHASE_AI_") || strings.HasPrefix(upper, "PHASE_AGENT_") {
			return fmt.Errorf("%s cannot override protected environment key %s", label, key)
		}
		if label == "configEnv" {
			if containsEnvironmentKey(phaseCredentialEnvironmentKeys, upper) || containsEnvironmentKey(credentialEnvironment, upper) {
				return fmt.Errorf("configEnv cannot provide credential environment key %s", key)
			}
		}
		for existing := range destination {
			if strings.EqualFold(existing, key) {
				return fmt.Errorf("%s duplicates environment key %s", label, key)
			}
		}
		destination[key] = value
	}
	return nil
}

// ValidProxyUsername accepts a default capability or an explicit connection selector.
func ValidProxyUsername(username string) bool {
	if username == "phase" {
		return true
	}
	if !strings.HasPrefix(username, "phase.") {
		return false
	}
	value := strings.TrimPrefix(username, "phase.")
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
