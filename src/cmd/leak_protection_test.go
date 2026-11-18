package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/phase"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// downSession makes the process look like it runs inside a Phase AI session
// whose proxy is not listening.
func downSession(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@" + address}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	t.Cleanup(func() { leakguard.Environment = previous })
}

func captureLeakWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previous := leakWarnings
	leakWarnings = &buffer
	t.Cleanup(func() { leakWarnings = previous })
	return &buffer
}

var leakTestSecrets = []sdk.SecretResult{
	{Key: "STRIPE_KEY", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS", Type: "secret", Path: "/"},
	{Key: "LOG_LEVEL", Value: "debug", Type: "config", Path: "/"},
}

func TestAgentLoginRefusesWhenLeakProtectionIsDown(t *testing.T) {
	downSession(t)
	warnings := captureLeakWarnings(t)
	err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets)
	if !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login carried on without leak protection: %v", err)
	}
	if !strings.Contains(err.Error(), "phase ai status") || strings.Contains(err.Error(), "sk_live") || strings.Count(err.Error(), "\n") != 0 {
		t.Fatalf("the refusal is not one clear line: %q", err.Error())
	}
	if warnings.Len() != 0 {
		t.Fatal("an Agent refusal also printed a warning")
	}
}

func TestOtherLoginsWarnOnceAndCarryOn(t *testing.T) {
	downSession(t)
	warnings := captureLeakWarnings(t)
	if err := protectValues(context.Background(), false, []leakguard.Value{{Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value}}); err != nil {
		t.Fatalf("a personal login was refused: %v", err)
	}
	if got := warnings.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "phase ai status") || strings.Contains(got, "sk_live") {
		t.Fatalf("warning: %q", got)
	}
}

func TestNothingIsRegisteredOutsideASessionOrForConfig(t *testing.T) {
	calls := 0
	previous := leakRegister
	leakRegister = func(context.Context, []leakguard.Value) (leakguard.Result, error) {
		calls++
		return leakguard.Result{}, errors.New("unreachable")
	}
	t.Cleanup(func() { leakRegister = previous })
	previousEnvironment := leakguard.Environment
	leakguard.Environment = func(string) string { return "" }
	t.Cleanup(func() { leakguard.Environment = previousEnvironment })
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil || calls != 0 {
		t.Fatalf("outside a session: %v, %d calls", err, calls)
	}
	downSession(t)
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets[1:]); err != nil || calls != 0 {
		t.Fatalf("config values were registered: %v, %d calls", err, calls)
	}
	var registered []leakguard.Value
	leakRegister = func(_ context.Context, values []leakguard.Value) (leakguard.Result, error) {
		registered = values
		return leakguard.Result{Added: len(values)}, nil
	}
	dynamic := sdk.SecretResult{Key: "DB_PASSWORD", Value: "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3", IsDynamic: true}
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, append(leakTestSecrets, dynamic)); err != nil {
		t.Fatal(err)
	}
	if len(registered) != 2 || registered[0].Type != "secret" || registered[0].ID != "STRIPE_KEY" || registered[1].Type != "dynamic" {
		t.Fatalf("registered: %+v", registered)
	}
}

func TestLeaseCredentialsAreFoundInADynamicSecretsResponse(t *testing.T) {
	payload := []byte(`[{"id":"ds-1","name":"db","lease":{"id":"lease-123","credentials":[{"key":"DB_USER","value":"phase_user_8f2k"},{"key":"DB_PASSWORD","value":"Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3"}]}},{"id":"ds-2","lease":null}]`)
	var values []leakguard.Value
	var root any
	_ = json.Unmarshal(payload, &root)
	collectLeaseCredentials(root, &values, 0)
	if len(values) != 2 || values[0].Type != "dynamic" || values[0].ID != "lease-123" || values[1].Value != "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3" {
		t.Fatalf("lease credentials: %+v", values)
	}
}

func TestStatusLineSummarisesLeakProtection(t *testing.T) {
	line := leakProtectionSummary(remoteapi.LeakProtectionStatus{
		Mode: "censor", SecretsKnown: 12, Unprotected: 1,
		InspectedHosts: []string{"api.anthropic.com"}, UnreadHosts: []string{"*.cursor.sh", "opencode.ai"},
	})
	want := "censor (secrets in model traffic are replaced with placeholders); 12 secrets known, 1 too short or plain to protect; not inspected: *.cursor.sh, opencode.ai"
	if line != want {
		t.Fatalf("status line:\n%s\n%s", line, want)
	}
	if line := leakProtectionSummary(remoteapi.LeakProtectionStatus{Mode: "off", SecretsKnown: 1}); line != "off (model traffic is not inspected); 1 secret known" {
		t.Fatalf("off: %s", line)
	}
}

// A full inventory says so, for an Agent and for anyone else, and never
// claims the proxy could not be reached.
func TestAFullInventoryHasItsOwnMessage(t *testing.T) {
	downSession(t)
	previous := leakRegister
	leakRegister = func(context.Context, []leakguard.Value) (leakguard.Result, error) {
		return leakguard.Result{}, leakguard.ErrInventoryFull
	}
	t.Cleanup(func() { leakRegister = previous })
	values := []leakguard.Value{{Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value}}
	warnings := captureLeakWarnings(t)
	err := protectValues(context.Background(), true, values)
	if !errors.Is(err, errLeakInventoryFull) || !strings.Contains(err.Error(), "full") || strings.Contains(err.Error(), "reach") ||
		!strings.Contains(err.Error(), "Restarting the Phase AI proxy") {
		t.Fatalf("Agent: %v", err)
	}
	if err := protectValues(context.Background(), false, values); err != nil {
		t.Fatal(err)
	}
	if got := warnings.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "full") || strings.Contains(got, "reach") {
		t.Fatalf("warning: %q", got)
	}
}

// An Agent login handing out values outside a session is told once, on the
// warning stream, that nothing is protected, and is not refused.
func TestAgentLoginOutsideASessionIsToldOnce(t *testing.T) {
	previousEnvironment := leakguard.Environment
	leakguard.Environment = func(string) string { return "" }
	t.Cleanup(func() { leakguard.Environment = previousEnvironment })
	inactiveNotice = sync.Once{}
	t.Cleanup(func() { inactiveNotice = sync.Once{} })
	warnings := captureLeakWarnings(t)
	for i := 0; i < 3; i++ {
		if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
			t.Fatalf("an Agent login outside a session was refused: %v", err)
		}
	}
	if got := warnings.String(); got != leakProtectionInactiveMsg+"\n" || strings.Contains(got, "sk_live") {
		t.Fatalf("notice: %q", got)
	}
	// Only config values: nothing is handed out that needs protecting.
	inactiveNotice = sync.Once{}
	warnings.Reset()
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets[1:]); err != nil || warnings.Len() != 0 {
		t.Fatalf("config only: %v %q", err, warnings.String())
	}
}
