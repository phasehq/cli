package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryKeyring struct {
	values   map[string]string
	setError error
}

func (m *memoryKeyring) Get(service, user string) (string, error) {
	value, ok := m.values[service+"/"+user]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

func (m *memoryKeyring) Set(service, user, value string) error {
	if m.setError != nil {
		return m.setError
	}
	m.values[service+"/"+user] = value
	return nil
}

func TestCAStoreFallsBackToOwnerOnlyKeyFileWithoutKeyring(t *testing.T) {
	directory := t.TempDir()
	store := CAStore{
		Directory: directory,
		Keyring:   &memoryKeyring{values: make(map[string]string), setError: errors.New("headless keyring unavailable")},
	}
	first, _, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(directory, "ca-key.pem")
	info, err := os.Lstat(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("fallback private key mode=%v", info.Mode())
	}
	payload, err := os.ReadFile(privateKeyPath)
	if err != nil || !strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatalf("fallback private key is invalid: %v", err)
	}
	second, _, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if first.cert.SerialNumber.Cmp(second.cert.SerialNumber) != 0 {
		t.Fatal("headless fallback did not preserve the per-installation CA")
	}
}

func TestCAStorePersistsPrivateMaterialOnlyInKeyring(t *testing.T) {
	directory := t.TempDir()
	keyring := &memoryKeyring{values: make(map[string]string)}
	store := CAStore{Directory: directory, Keyring: keyring}
	first, paths, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("expected CA")
	}
	for _, path := range []string{paths.Certificate, paths.Bundle} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "PRIVATE KEY") {
			t.Fatalf("private key was written to %s", path)
		}
	}
	privatePEM := keyring.values[caKeyringService+"/"+caKeyringUser]
	if !strings.Contains(privatePEM, "PRIVATE KEY") {
		t.Fatal("private key was not stored in keyring")
	}

	certBefore, err := os.ReadFile(paths.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPaths, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	certAfter, err := os.ReadFile(secondPaths.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if string(certBefore) != string(certAfter) || first.cert.SerialNumber.Cmp(second.cert.SerialNumber) != 0 {
		t.Fatal("existing CA was not reused")
	}
	if filepath.Dir(paths.Bundle) != directory {
		t.Fatal("CA bundle escaped configured directory")
	}
}

func TestCAStoreRenewsCertificateNearExpiryAndKeepsFreshOnes(t *testing.T) {
	directory := t.TempDir()
	keyring := &memoryKeyring{values: make(map[string]string)}
	// An existing CA with five days left is inside the renewal window.
	expiring, certPEM, keyPEM, err := GenerateCA(5 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyring.values[caKeyringService+"/"+caKeyringUser] = string(keyPEM)
	store := CAStore{Directory: directory, Keyring: keyring, Validity: 365 * 24 * time.Hour}
	renewed, paths, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if !paths.Renewed || renewed.cert.SerialNumber.Cmp(expiring.cert.SerialNumber) == 0 {
		t.Fatalf("expiring CA was not renewed: renewed=%v", paths.Renewed)
	}
	if paths.NotAfter.Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("renewed CA expiry = %s", paths.NotAfter)
	}
	if !strings.Contains(keyring.values[caKeyringService+"/"+caKeyringUser], "PRIVATE KEY") || keyring.values[caKeyringService+"/"+caKeyringUser] == string(keyPEM) {
		t.Fatal("renewed CA did not replace the private key")
	}
	kept, keptPaths, err := store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if keptPaths.Renewed || kept.cert.SerialNumber.Cmp(renewed.cert.SerialNumber) != 0 {
		t.Fatal("freshly renewed CA was renewed again")
	}

	// Sixty days left on a ninety-day CA is outside the fourteen-day window.
	fresh := t.TempDir()
	freshKeyring := &memoryKeyring{values: make(map[string]string)}
	healthy, healthyPEM, healthyKey, err := GenerateCA(60 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "ca.pem"), healthyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	freshKeyring.values[caKeyringService+"/"+caKeyringUser] = string(healthyKey)
	loaded, loadedPaths, err := (CAStore{Directory: fresh, Keyring: freshKeyring}).Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if loadedPaths.Renewed || loaded.cert.SerialNumber.Cmp(healthy.cert.SerialNumber) != 0 || !loadedPaths.NotAfter.Equal(healthy.cert.NotAfter) {
		t.Fatal("healthy CA was replaced")
	}
	if defaultCAValidity != 90*24*time.Hour {
		t.Fatalf("default CA validity = %s, want 90 days", defaultCAValidity)
	}

	// A CA issued under the old ten-year policy is replaced on first use.
	legacy := t.TempDir()
	legacyKeyring := &memoryKeyring{values: make(map[string]string)}
	old, oldPEM, oldKey, err := GenerateCA(10 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "ca.pem"), oldPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyKeyring.values[caKeyringService+"/"+caKeyringUser] = string(oldKey)
	replaced, replacedPaths, err := (CAStore{Directory: legacy, Keyring: legacyKeyring}).Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if !replacedPaths.Renewed || replaced.cert.SerialNumber.Cmp(old.cert.SerialNumber) == 0 || replacedPaths.NotAfter.After(time.Now().Add(91*24*time.Hour)) {
		t.Fatalf("legacy long-lived CA was kept: renewed=%v notAfter=%s", replacedPaths.Renewed, replacedPaths.NotAfter)
	}
}

// pausingKeyring holds the first Set until release is closed or a short wait
// passes, leaving room for a second Ensure to run unless Ensure serializes.
type pausingKeyring struct {
	mu       sync.Mutex
	values   map[string]string
	sets     int
	firstSet chan struct{}
	release  chan struct{}
}

func (k *pausingKeyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.values[service+"/"+user]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

func (k *pausingKeyring) Set(service, user, value string) error {
	k.mu.Lock()
	k.values[service+"/"+user] = value
	k.sets++
	first := k.sets == 1
	k.mu.Unlock()
	if first {
		close(k.firstSet)
		select {
		case <-k.release:
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

func TestCAStoreConcurrentRenewalPublishesOneConsistentCA(t *testing.T) {
	directory := t.TempDir()
	_, certPEM, keyPEM, err := GenerateCA(5 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyring := &pausingKeyring{
		values:   map[string]string{caKeyringService + "/" + caKeyringUser: string(keyPEM)},
		firstSet: make(chan struct{}), release: make(chan struct{}),
	}
	store := CAStore{Directory: directory, Keyring: keyring, Validity: 365 * 24 * time.Hour}
	type ensured struct {
		ca  *CA
		err error
	}
	firstDone := make(chan ensured, 1)
	go func() {
		ca, _, err := store.Ensure()
		firstDone <- ensured{ca, err}
	}()
	<-keyring.firstSet
	second, _, secondErr := store.Ensure()
	close(keyring.release)
	first := <-firstDone
	if first.err != nil || secondErr != nil {
		t.Fatalf("Ensure failed: %v, %v", first.err, secondErr)
	}

	publishedPEM, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	storedKey, _ := keyring.Get(caKeyringService, caKeyringUser)
	published, err := LoadCA(publishedPEM, []byte(storedKey))
	if err != nil {
		t.Fatalf("published certificate does not match the stored key: %v", err)
	}
	for _, ca := range []*CA{first.ca, second} {
		if ca.cert.SerialNumber.Cmp(published.cert.SerialNumber) != 0 {
			t.Fatal("an Ensure caller is serving a CA that was not published")
		}
	}
}

func TestComposeEnvironmentExcludesDurableTokensAndIncludesCompatibilityVariables(t *testing.T) {
	environment, err := composeTestEnvironment(EnvironmentOptions{
		Base: []string{
			"PATH=/usr/bin",
			"PHASE_SERVICE_TOKEN=durable-user-token",
			"PHASE_AGENT_TOKEN=durable-agent-token",
			"GH_TOKEN=ambient-github-token",
			"AWS_PROFILE=ambient-admin-profile",
			"DATABASE_URL=postgres://ambient:password@database.internal/app",
			"AWS_SESSION_TOKEN=ambient-session-token",
			"AWS_REGION=old-region",
		},
		ProxyURL:         "http://phase:runtime-capability@127.0.0.1:7777",
		CertificatePath:  "/tmp/phase-ca.pem",
		CABundlePath:     "/tmp/phase-ca-bundle.pem",
		CABundleComplete: true,
		ConfigEnv:        map[string]string{"AWS_REGION": "us-east-1"},
		AgentEnv:         map[string]string{"AWS_ACCESS_KEY_ID": "AKIAEXAMPLEIDENTIFIER", "AWS_SECRET_ACCESS_KEY": "decoy-only"},
		EnvironmentBindings: []EnvironmentBinding{
			{Name: "AWS_ACCESS_KEY_ID", Action: "set", Source: "identifier", SourceField: "access_key_id"},
			{Name: "AWS_SECRET_ACCESS_KEY", Action: "set", Source: "decoy", SourceField: "secret_access_key"},
			{Name: "AWS_REGION", Action: "set", Source: "connection_config", SourceField: "region"},
			{Name: "AWS_PROFILE", Action: "unset", Source: "runtime", SourceField: "secret_access_key"},
			{Name: "AWS_SESSION_TOKEN", Action: "unset", Source: "runtime", SourceField: "secret_access_key"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{
		"durable-user-token", "durable-agent-token", "ambient-session-token", "PHASE_SERVICE_TOKEN=", "PHASE_AGENT_TOKEN=",
		"PHASE_AI_SESSION_UID=",
		"PHASE_AI_SESSION_CREDENTIAL=", "PHASE_AGENT_SESSION_CREDENTIAL=", "PHASE_AI_CONTROL_URL=",
		"AWS_PROFILE=ambient-admin-profile",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("child environment leaked %q:\n%s", forbidden, joined)
		}
	}
	for _, required := range []string{
		"HTTPS_PROXY=http://phase:runtime-capability@127.0.0.1:7777",
		"REQUESTS_CA_BUNDLE=/tmp/phase-ca-bundle.pem",
		"NODE_EXTRA_CA_CERTS=/tmp/phase-ca-bundle.pem",
		"NO_PROXY=127.0.0.1,localhost,::1",
		"AWS_REGION=us-east-1",
		"AWS_SECRET_ACCESS_KEY=decoy-only",
		"GH_TOKEN=ambient-github-token",
		"DATABASE_URL=postgres://ambient:password@database.internal/app",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("child environment missing %q:\n%s", required, joined)
		}
	}
}

func TestComposeEnvironmentRejectsProtectedOrCollidingAgentKeys(t *testing.T) {
	base := EnvironmentOptions{
		ProxyURL: "http://phase:capability@127.0.0.1:7777", CertificatePath: "/ca.pem", CABundlePath: "/bundle.pem",
	}
	base.AgentEnv = map[string]string{"PHASE_SERVICE_TOKEN": "live"}
	if _, err := composeTestEnvironment(base); err == nil {
		t.Fatal("expected protected key rejection")
	}
	base.AgentEnv = map[string]string{"AWS_REGION": "other"}
	base.ConfigEnv = map[string]string{"AWS_REGION": "us-east-1"}
	if _, err := composeTestEnvironment(base); err == nil {
		t.Fatal("expected config/agent collision rejection")
	}
	base.AgentEnv = nil
	base.ConfigEnv = map[string]string{"SAFE; touch /tmp/phase-owned": "value"}
	if _, err := composeTestEnvironment(base); err == nil {
		t.Fatal("expected shell-unsafe environment key rejection")
	}
}

func TestComposeEnvironmentReservedPrecedenceAndPreservesUserJavaOptions(t *testing.T) {
	options := EnvironmentOptions{
		Base: []string{
			"AWS_REGION=inherited", "NO_PROXY=attacker.example", "no_proxy=attacker.example",
			"JAVA_TOOL_OPTIONS=-Xmx256m -Djavax.net.ssl.trustStore=/attacker", "GITHUB_TOKEN=ambient-live-token",
		},
		ProxyURL:        "http://phase:capability@127.0.0.1:7777",
		CertificatePath: "/tmp/phase ca.pem", CABundlePath: "/tmp/phase bundle.pem", CABundleComplete: true,
		ConfigEnv: map[string]string{"AWS_REGION": "configured"}, AgentEnv: map[string]string{"GITHUB_TOKEN": "decoy"},
		EnvironmentBindings: []EnvironmentBinding{
			{Name: "AWS_REGION", Action: "set", Source: "connection_config", SourceField: "region"},
			{Name: "GITHUB_TOKEN", Action: "set", Source: "decoy", SourceField: "access_token"},
		},
	}
	environment, err := composeTestEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	if values["AWS_REGION"] != "configured" {
		t.Fatalf("config did not override inherited: %q", values["AWS_REGION"])
	}
	if values["GITHUB_TOKEN"] != "decoy" {
		t.Fatalf("ambient credential survived adapter precedence: %q", values["GITHUB_TOKEN"])
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if values[key] != "127.0.0.1,localhost,::1,attacker.example" {
			t.Fatalf("%s = %q", key, values[key])
		}
	}
	java := values["JAVA_TOOL_OPTIONS"]
	if java != "-Xmx256m -Djavax.net.ssl.trustStore=/attacker" {
		t.Fatalf("unrelated JAVA_TOOL_OPTIONS was copied or clobbered: %q", java)
	}

	for _, protected := range []string{"NO_PROXY", "no_proxy", "JAVA_TOOL_OPTIONS", "PHASE_AI_CONTROL_URL"} {
		copy := options
		copy.ConfigEnv = map[string]string{protected: "hostile"}
		if _, err := composeTestEnvironment(copy); err == nil {
			t.Fatalf("config overrode reserved %s", protected)
		}
	}
}

func TestComposeEnvironmentPreservesUnrelatedProviderCAConfiguration(t *testing.T) {
	options := EnvironmentOptions{
		Base:     []string{"AWS_CA_BUNDLE=/user/aws-ca.pem", "PGSSLROOTCERT=/user/postgres-ca.pem"},
		ProxyURL: "http://phase:capability@127.0.0.1:7777", CertificatePath: "/ca.pem", CABundlePath: "/phase-bundle.pem",
	}
	environment, err := composeTestEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	for _, expected := range []string{"AWS_CA_BUNDLE=/user/aws-ca.pem", "PGSSLROOTCERT=/user/postgres-ca.pem"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("unrelated provider CA was replaced: missing %s in %s", expected, joined)
		}
	}

	options.AgentEnv = map[string]string{"AWS_ACCESS_KEY_ID": "decoy", "AWS_SECRET_ACCESS_KEY": "decoy-secret"}
	options.EnvironmentBindings = []EnvironmentBinding{
		{Name: "AWS_ACCESS_KEY_ID", Action: "set", Source: "identifier", SourceField: "access_key_id"},
		{Name: "AWS_SECRET_ACCESS_KEY", Action: "set", Source: "decoy", SourceField: "secret_access_key"},
	}
	environment, err = composeTestEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(environment, "\n")
	if !strings.Contains(joined, "AWS_CA_BUNDLE=/phase-bundle.pem") || !strings.Contains(joined, "PGSSLROOTCERT=/user/postgres-ca.pem") {
		t.Fatalf("provider-specific CA planning was not conditional: %s", joined)
	}
}

func TestComposeEnvironmentRequiresAuthenticatedProxyAndTLSOffLoopback(t *testing.T) {
	options := EnvironmentOptions{
		ProxyURL:        "http://127.0.0.1:7777",
		CertificatePath: "/ca", CABundlePath: "/bundle",
	}
	if _, err := composeTestEnvironment(options); err == nil {
		t.Fatal("expected unauthenticated proxy URL rejection")
	}
	options.ProxyURL = "http://phase:capability@example.com:7777"
	if _, err := composeTestEnvironment(options); err == nil {
		t.Fatal("expected non-loopback plaintext proxy URL rejection")
	}
}

func TestCompileProcessEnvironmentUsesExplicitCleanupAndSanitizesNoProxy(t *testing.T) {
	plan, err := CompileProcessEnvironment(EnvironmentOptions{
		Base: []string{
			"AWS_PROFILE=ambient-admin", "AWS_CONFIG_FILE=/home/user/.aws/config",
			"AWS_SESSION_TOKEN=ambient-session-token",
			"NO_PROXY=*,phase.invalid,.amazonaws.com,metadata.internal,127.0.0.1,https://secret.example,token@host,bad value,/tmp/secret",
			"no_proxy=sts.us-east-1.amazonaws.com,corp.internal,good.example:443",
		},
		ProxyURL:     "http://phase:capability@127.0.0.1:9543",
		CABundlePath: "/stable/runtime-ca-bundle.pem",
		AgentEnv: map[string]string{
			"AWS_ACCESS_KEY_ID": "agent-id", "AWS_SECRET_ACCESS_KEY": "decoy",
			"AWS_SESSION_TOKEN": "decoy-session-token",
		},
		CredentialFamilies: []string{"aws"},
		EnvironmentBindings: []EnvironmentBinding{
			{Name: "AWS_ACCESS_KEY_ID", Action: "set", Source: "identifier", SourceField: "access_key_id"},
			{Name: "AWS_SECRET_ACCESS_KEY", Action: "set", Source: "decoy", SourceField: "secret_access_key"},
			{Name: "AWS_SESSION_TOKEN", Action: "set", Source: "decoy", SourceField: "session_token"},
			{Name: "AWS_PROFILE", Action: "unset", Source: "runtime", SourceField: "secret_access_key"},
		},
		ProxyRequiredHosts: []string{".amazonaws.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Set["AWS_CA_BUNDLE"] != "/stable/runtime-ca-bundle.pem" {
		t.Fatalf("AWS first-call trust was not installed for an incomplete bundle: %+v", plan.Set)
	}
	if !containsEnvironmentKey(plan.Unset, "AWS_PROFILE") || containsEnvironmentKey(plan.Unset, "AWS_CONFIG_FILE") {
		t.Fatalf("explicit AWS cleanup was not bounded: %+v", plan.Unset)
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if plan.Set[key] != "127.0.0.1,localhost,::1,metadata.internal,corp.internal,good.example:443" {
			t.Fatalf("%s was not safely preserved and sanitized: %q", key, plan.Set[key])
		}
	}
	environment, err := ApplyProcessEnvironment([]string{
		"AWS_PROFILE=ambient-admin", "AWS_CONFIG_FILE=/home/user/.aws/config", "AWS_SESSION_TOKEN=ambient-session-token",
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "AWS_PROFILE=") || !strings.Contains(joined, "AWS_CONFIG_FILE=/home/user/.aws/config") {
		t.Fatalf("application mutated the wrong AWS state: %s", joined)
	}
	if !strings.Contains(joined, "AWS_SESSION_TOKEN=decoy-session-token") || strings.Contains(joined, "ambient-session-token") {
		t.Fatalf("managed AWS session token did not replace ambient state: %s", joined)
	}
}

func TestApplyProcessEnvironmentKeepsInheritedNamesThatAreNotShellIdentifiers(t *testing.T) {
	environment, err := ApplyProcessEnvironment([]string{
		`ProgramFiles(x86)=C:\Program Files (x86)`,
		`CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files`,
		"BASH_FUNC_module%%=() {  :\n}",
		`=C:=C:\work`,
		"AWS_PROFILE=ambient-admin",
		"AWS_ACCESS_KEY_ID=ambient",
	}, ProcessEnvironmentPlan{Set: map[string]string{"AWS_ACCESS_KEY_ID": "decoy"}, Unset: []string{"AWS_PROFILE"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	for _, entry := range []string{`ProgramFiles(x86)=C:\Program Files (x86)`, `CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files`, "BASH_FUNC_module%%=() {  :\n}", "AWS_ACCESS_KEY_ID=decoy"} {
		if !strings.Contains(joined, "\n"+entry+"\n") {
			t.Fatalf("missing %q in %q", entry, environment)
		}
	}
	for _, entry := range environment {
		if strings.HasPrefix(entry, "=") || strings.HasPrefix(entry, "AWS_PROFILE=") || entry == "AWS_ACCESS_KEY_ID=ambient" {
			t.Fatalf("hidden drive entry, unset or overridden value survived: %q", environment)
		}
	}
}

func TestCompileProcessEnvironmentRejectsBindingAndAdapterCollisions(t *testing.T) {
	base := EnvironmentOptions{
		ProxyURL: "http://phase:capability@127.0.0.1:9543", CABundlePath: "/bundle.pem",
		AgentEnv: map[string]string{"PGPASSWORD": "decoy"}, CredentialFamilies: []string{"postgres"},
		EnvironmentBindings: []EnvironmentBinding{{Name: "PGPASSWORD", Action: "set", Source: "decoy", SourceField: "password"}},
	}
	base.AdapterEnv = map[string]string{"PGPASSWORD": "different"}
	if _, err := CompileProcessEnvironment(base); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("differing adapter collision error = %v", err)
	}
	base.AdapterEnv = map[string]string{"PGPASSWORD": "decoy"}
	if _, err := CompileProcessEnvironment(base); err != nil {
		t.Fatalf("matching adapter resolution was rejected: %v", err)
	}
	base.EnvironmentBindings = append(base.EnvironmentBindings, EnvironmentBinding{Name: "PGPASSWORD", Action: "set", Source: "decoy", SourceField: "password"})
	if _, err := CompileProcessEnvironment(base); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate binding provenance error = %v", err)
	}
	base.EnvironmentBindings = base.EnvironmentBindings[:1]
	base.AgentEnv["UNDECLARED"] = "value"
	if _, err := CompileProcessEnvironment(base); err == nil || !strings.Contains(err.Error(), "no environment binding") {
		t.Fatalf("undeclared agent environment error = %v", err)
	}
	delete(base.AgentEnv, "UNDECLARED")
	base.EnvironmentBindings[0].Source = "connection_config"
	if _, err := CompileProcessEnvironment(base); err == nil || !strings.Contains(err.Error(), "configEnv") {
		t.Fatalf("cross-plane binding provenance error = %v", err)
	}
}

func TestModernEnvironmentContractRejectsSetUnsetCollisions(t *testing.T) {
	_, err := PlanResolvedProcessEnvironment(
		map[string]string{"CUSTOM_CONTEXT": "configured"},
		map[string]string{},
		[]EnvironmentBinding{{Name: "CUSTOM_CONTEXT", Action: "unset", Source: "runtime", SourceField: "activation"}},
	)
	if err == nil || !strings.Contains(err.Error(), "both set and unset") {
		t.Fatalf("provider set/unset collision error = %v", err)
	}

	_, err = CompileProcessEnvironment(EnvironmentOptions{
		ProxyURL: "http://phase:capability@127.0.0.1:9543", CABundlePath: "/bundle.pem",
		AdapterEnv: map[string]string{"PGPASSWORD": "adapter-decoy"},
		EnvironmentBindings: []EnvironmentBinding{{
			Name: "PGPASSWORD", Action: "unset", Source: "runtime", SourceField: "password",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "both set and unset") {
		t.Fatalf("adapter set/unset collision error = %v", err)
	}

	_, err = PlanResolvedProcessEnvironment(
		map[string]string{"AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/admin"}, nil, []EnvironmentBinding{},
	)
	if err == nil || !strings.Contains(err.Error(), "credential environment key") {
		t.Fatalf("credential-shaped configEnv error = %v", err)
	}
}

func TestProcessEnvironmentPlanFormattingRedactsValuesButJSONRetainsAuthenticatedPayload(t *testing.T) {
	plan := ProcessEnvironmentPlan{
		Set:   map[string]string{"HTTPS_PROXY": "http://phase:runtime-secret@127.0.0.1:9543", "AWS_SECRET_ACCESS_KEY": "decoy-secret"},
		Unset: []string{"AWS_PROFILE"},
	}
	formatted := fmt.Sprintf("%v %+v %#v", plan, plan, plan)
	for _, secret := range []string{"runtime-secret", "decoy-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("process environment formatting leaked %q: %s", secret, formatted)
		}
	}
	if !strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("process environment formatting did not signal redaction: %s", formatted)
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"runtime-secret", "decoy-secret"} {
		if !bytes.Contains(payload, []byte(required)) {
			t.Fatalf("authenticated JSON omitted %q: %s", required, payload)
		}
	}
}

func TestMergeCustomCABundlePreservesPublicRootsAndRejectsPrivateKeys(t *testing.T) {
	_, phaseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, customCertificate, customPrivateKey, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	phasePath := filepath.Join(directory, "phase.pem")
	customPath := filepath.Join(directory, "custom.pem")
	if err := os.WriteFile(phasePath, phaseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customPath, append(append([]byte(nil), customCertificate...), customPrivateKey...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mergeTestCABundle(phasePath, []string{"SSL_CERT_FILE=" + customPath}, nil); err == nil || !strings.Contains(err.Error(), "private-key material") {
		t.Fatalf("private-key-bearing CA source was accepted: %v", err)
	}
	if err := os.WriteFile(customPath, customCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	mergedPath, cleanup, err := mergeTestCABundle(phasePath, []string{"SSL_CERT_FILE=" + customPath, "REQUESTS_CA_BUNDLE=" + customPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mergedPath == phasePath {
		t.Fatal("custom CA source did not produce a process-local merged bundle")
	}
	merged, err := os.ReadFile(mergedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(merged, phaseCertificate) || !bytes.Contains(merged, customCertificate) || bytes.Contains(merged, []byte("PRIVATE KEY")) {
		t.Fatalf("merged CA bundle did not preserve only public certificates: %s", merged)
	}
	cleanup()
	if _, err := os.Stat(mergedPath); !os.IsNotExist(err) {
		t.Fatalf("temporary merged CA bundle survived cleanup: %v", err)
	}
	if path, cleanup, err := mergeTestCABundle(phasePath, []string{"AWS_CA_BUNDLE=/missing/unrelated.pem"}, nil); err != nil || path == "" {
		t.Fatalf("unrelated AWS CA became a run precondition: path=%q err=%v", path, err)
	} else {
		cleanup()
	}
	if _, _, err := mergeTestCABundle(phasePath, []string{"AWS_CA_BUNDLE=/missing/active.pem"}, []string{"aws"}); err == nil {
		t.Fatal("active AWS custom CA failure was silently discarded")
	}
}

func TestPreparedCABundleWindowsFallbackPreservesEnterpriseTrustConfiguration(t *testing.T) {
	_, phaseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, enterpriseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	phasePath := filepath.Join(directory, "phase.pem")
	enterprisePath := filepath.Join(directory, "enterprise.pem")
	if err := os.WriteFile(phasePath, phaseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enterprisePath, enterpriseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	baseEnvironment := []string{
		"SSL_CERT_DIR=C:\\enterprise\\hashed-roots",
		"NODE_EXTRA_CA_CERTS=" + enterprisePath,
	}
	prepared, cleanup, err := prepareProcessCABundle(phasePath, baseEnvironment, nil, "windows", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if prepared.Complete {
		t.Fatalf("Windows additive-only roots were treated as a complete replacement bundle: %+v", prepared)
	}
	environment, err := composeTestEnvironment(EnvironmentOptions{
		Base: baseEnvironment, ProxyURL: "http://phase:capability@127.0.0.1:9543",
		CertificatePath: phasePath, CABundlePath: prepared.BundlePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	for _, expected := range []string{
		"SSL_CERT_DIR=C:\\enterprise\\hashed-roots",
		"NODE_EXTRA_CA_CERTS=" + prepared.BundlePath,
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("incomplete Windows fallback dropped additive trust %q: %s", expected, joined)
		}
	}
	for _, forbidden := range []string{"SSL_CERT_FILE=", "REQUESTS_CA_BUNDLE=", "CURL_CA_BUNDLE=", "JAVA_TOOL_OPTIONS="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("incomplete Windows bundle installed unsafe replacement %q: %s", forbidden, joined)
		}
	}
}

func TestPreparedCABundleWindowsMergesAndDeduplicatesInheritedCompleteBundle(t *testing.T) {
	_, phaseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, enterpriseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	phasePath := filepath.Join(directory, "phase.pem")
	enterprisePath := filepath.Join(directory, "enterprise.pem")
	if err := os.WriteFile(phasePath, phaseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enterprisePath, enterpriseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, cleanup, err := prepareProcessCABundle(phasePath, []string{
		"SSL_CERT_FILE=" + enterprisePath,
		"REQUESTS_CA_BUNDLE=" + enterprisePath,
	}, nil, "windows", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !prepared.Complete {
		t.Fatalf("inherited complete bundle was not usable on Windows: %+v", prepared)
	}
	certificates, err := readBoundedPublicCertificates(prepared.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 {
		t.Fatalf("merged bundle contains %d certificates, want Phase + one deduplicated enterprise root", len(certificates))
	}
}

func TestPreparedCABundleMergesEveryAvailableSystemBundle(t *testing.T) {
	directory := t.TempDir()
	paths := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		_, certificate, _, err := GenerateCA(time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, fmt.Sprintf("roots-%d.pem", index))
		if err := os.WriteFile(path, certificate, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	prepared, cleanup, err := prepareProcessCABundle(paths[0], nil, nil, "linux", paths[1:])
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	certificates, err := readBoundedPublicCertificates(prepared.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Complete || len(certificates) != 3 {
		t.Fatalf("system bundles were not all merged: complete=%t certificates=%d", prepared.Complete, len(certificates))
	}
}

func TestPrepareStableProcessCABundlePublishesPredictablePublicPath(t *testing.T) {
	_, phaseCertificate, _, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	basePath := filepath.Join(directory, "ca-bundle.pem")
	if err := os.WriteFile(basePath, phaseCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareStableProcessCABundle(basePath, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.BundlePath != filepath.Join(directory, "runtime-ca-bundle.pem") {
		t.Fatalf("stable bundle path = %q", prepared.BundlePath)
	}
	if _, err := readBoundedPublicCertificates(prepared.BundlePath); err != nil {
		t.Fatalf("stable bundle is not certificate-only: %v", err)
	}
	first, err := os.ReadFile(prepared.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PrepareStableProcessCABundle(basePath, nil, nil)
	if err != nil {
		t.Fatalf("repeat stable publication failed: %v", err)
	}
	second, err := os.ReadFile(repeated.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.BundlePath != prepared.BundlePath || string(first) != string(second) {
		t.Fatal("repeat stable publication changed the public bundle or its path")
	}
}

func TestComposeRemoteEnvironmentRequiresHTTPSAndOmitsBackendSessionCredential(t *testing.T) {
	options := EnvironmentOptions{
		Base:            []string{"PHASE_SERVICE_TOKEN=durable-token", "PATH=/usr/bin"},
		ProxyURL:        "https://phase:scoped-capability@remote.phase.test:8443",
		CertificatePath: "/remote/ca.pem",
		CABundlePath:    "/remote/ca-bundle.pem",
	}
	environment, err := composeTestEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	for _, required := range []string{
		"HTTPS_PROXY=https://phase:scoped-capability@remote.phase.test:8443",
		"PATH=/usr/bin",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("remote environment missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{
		"durable-token", "PHASE_SERVICE_TOKEN=", "PHASE_AI_SESSION_UID=",
		"PHASE_AI_SESSION_CREDENTIAL=", "PHASE_AGENT_SESSION_CREDENTIAL=", "PHASE_AI_CONTROL_URL=",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("remote environment contains %q:\n%s", forbidden, joined)
		}
	}
}

func composeTestEnvironment(options EnvironmentOptions) ([]string, error) {
	plan, err := CompileProcessEnvironment(options)
	if err != nil {
		return nil, err
	}
	return ApplyProcessEnvironment(options.Base, plan)
}

func mergeTestCABundle(baseBundlePath string, environment []string, credentialFamilies []string) (string, func(), error) {
	prepared, cleanup, err := PrepareProcessCABundle(baseBundlePath, environment, credentialFamilies)
	return prepared.BundlePath, cleanup, err
}
