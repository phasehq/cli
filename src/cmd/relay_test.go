package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/pkg/ai"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type scriptedRelayRuntime struct {
	calls int
	steps []func(ctx context.Context, engine *aiproxy.Engine) error
}

func (r *scriptedRelayRuntime) ServeManaged(ctx context.Context, engine airuntime.Engine) error {
	step := r.steps[r.calls]
	r.calls++
	return step(ctx, engine.(*aiproxy.Engine))
}

func relayTestEndpoints() aiproxy.Endpoints {
	return aiproxy.Endpoints{
		ProxyAddress: "relay.example.test:9543", ProxyURL: agentapi.SensitiveString("https://phase:relay-capability@relay.example.test:9543"),
		PostgresAddress: "relay.example.test:9544", Remote: true,
		Connections: []aiproxy.EndpointConnection{{ConnectionID: "aws-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}, {ConnectionID: "pg-1", ServiceType: "postgres", Protocol: "postgres"}},
	}
}

func TestRelayStartFlagsAndEngineDerivation(t *testing.T) {
	if err := relayStartCmd.ValidateRequiredFlags(); err == nil || !strings.Contains(err.Error(), "advertise-host") {
		t.Fatalf("relay start must require its TLS and host flags: %v", err)
	}
	t.Cleanup(func() {
		for name, value := range map[string]string{"listen": relayDefaultListenAddress, "advertise-host": "", "tls-cert": "", "tls-key": "", "lockdown": "false"} {
			_ = relayStartCmd.Flags().Set(name, value)
		}
	})
	for name, value := range map[string]string{"listen": "100.64.0.5:9543", "advertise-host": "relay.example.test", "tls-cert": "/tmp/chain.pem", "tls-key": "/tmp/key.pem", "lockdown": "true"} {
		if err := relayStartCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := relayEngineFromFlags(relayStartCmd)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.Remote || engine.ListenAddress != "100.64.0.5:9543" || engine.PostgresListenAddress != "100.64.0.5:9544" ||
		engine.AdvertiseHost != "relay.example.test" || engine.TLSCertificatePath != "/tmp/chain.pem" || engine.TLSPrivateKeyPath != "/tmp/key.pem" || !engine.Lockdown {
		t.Fatalf("unexpected relay engine: %+v", engine)
	}
	if len(engine.BootstrapSkills) == 0 {
		t.Fatal("relay must ship the Agent skill to sandboxes")
	}
	seen := make(map[string]bool)
	for _, skill := range engine.BootstrapSkills {
		if strings.HasPrefix(skill.Path, "/") || strings.Contains(skill.Path, "..") || !strings.HasSuffix(skill.Path, "/"+ai.AgentSkillName+"/SKILL.md") || seen[skill.Path] {
			t.Fatalf("unexpected bootstrap skill path %q", skill.Path)
		}
		seen[skill.Path] = true
		if !strings.Contains(skill.Content, "Automatic Phase environment") {
			t.Fatalf("bootstrap skill %s lacks the automatic environment guidance", skill.Path)
		}
	}
	if !seen[".claude/skills/"+ai.AgentSkillName+"/SKILL.md"] || !seen[".agents/skills/"+ai.AgentSkillName+"/SKILL.md"] {
		t.Fatalf("bootstrap skills = %v", seen)
	}
	if err := relayStartCmd.Flags().Set("listen", ":9543"); err != nil {
		t.Fatal(err)
	}
	engine, err = relayEngineFromFlags(relayStartCmd)
	if err != nil || engine.ListenAddress != "0.0.0.0:9543" || engine.PostgresListenAddress != "0.0.0.0:9544" {
		t.Fatalf("port-only listen must bind every interface: %+v err=%v", engine, err)
	}
	for _, invalid := range []string{"9543", "0.0.0.0:65535", "0.0.0.0:0", "0.0.0.0:port"} {
		if err := relayStartCmd.Flags().Set("listen", invalid); err != nil {
			t.Fatal(err)
		}
		if _, err := relayEngineFromFlags(relayStartCmd); err == nil {
			t.Fatalf("listen %q was accepted", invalid)
		}
	}
	if err := relayStartCmd.Flags().Set("listen", "0.0.0.0:19543"); err != nil {
		t.Fatal(err)
	}
	if engine, err := relayEngineFromFlags(relayStartCmd); err != nil || engine.PostgresListenAddress != "0.0.0.0:19544" {
		t.Fatalf("PostgreSQL adapter must follow the proxy port: %+v err=%v", engine, err)
	}
	if err := relayStartCmd.Flags().Set("listen", relayDefaultListenAddress); err != nil {
		t.Fatal(err)
	}
	rootsPath := filepath.Join(t.TempDir(), "roots.pem")
	t.Cleanup(func() { _ = relayStartCmd.Flags().Set("tls-ca", "") })
	if err := relayStartCmd.Flags().Set("tls-ca", rootsPath); err != nil {
		t.Fatal(err)
	}
	if _, err := relayEngineFromFlags(relayStartCmd); err == nil {
		t.Fatal("missing --tls-ca file was accepted")
	}
	if err := os.WriteFile(rootsPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relayEngineFromFlags(relayStartCmd); err == nil {
		t.Fatal("--tls-ca without certificates was accepted")
	}
	_, rootPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootsPath, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err = relayEngineFromFlags(relayStartCmd)
	if err != nil || engine.RemoteRootCAs == nil {
		t.Fatalf("--tls-ca roots were not loaded: %v", err)
	}
}

func TestRelayHandoffLineCarriesOnlyTheProxyURL(t *testing.T) {
	endpoints := relayTestEndpoints()
	line := relayHandoffLine(endpoints)
	if line != `eval "$(curl -fsS --proxy 'https://phase:relay-capability@relay.example.test:9543' http://phase.invalid/v1/bootstrap)"` {
		t.Fatalf("handoff line = %s", line)
	}
	ready := formatRelayReady(endpoints, line)
	for _, required := range []string{"Proxy:       https://relay.example.test:9543", "PostgreSQL:  relay.example.test:9544", "aws-prod (aws), pg-1 (postgres)", line} {
		if !strings.Contains(ready, required) {
			t.Fatalf("ready banner missing %q:\n%s", required, ready)
		}
	}
	if strings.Count(ready, "relay-capability") != 1 {
		t.Fatalf("the credential must appear exactly once, in the handoff line:\n%s", ready)
	}
}

func TestRelayLoopRecyclesSessionsOnOneEngineAndPrintsHandoffOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := aiproxy.New()
	var out, errOut bytes.Buffer
	runtime := &scriptedRelayRuntime{steps: []func(context.Context, *aiproxy.Engine) error{
		func(_ context.Context, engine *aiproxy.Engine) error {
			engine.OnStarted(relayTestEndpoints())
			return airuntime.ErrSessionExpired
		},
		func(_ context.Context, engine *aiproxy.Engine) error {
			engine.OnStarted(relayTestEndpoints())
			return airuntime.ErrSessionReprovisionRequired
		},
		func(_ context.Context, engine *aiproxy.Engine) error {
			engine.OnStarted(relayTestEndpoints())
			cancel()
			return nil
		},
	}}
	if err := runRelayLoop(ctx, strings.NewReader(""), &out, &errOut, runtime, engine); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 3 {
		t.Fatalf("expected three sessions on one engine, got %d", runtime.calls)
	}
	output := out.String()
	if strings.Count(output, "Phase AI relay ready") != 1 || strings.Count(output, "relay-capability") != 1 {
		t.Fatalf("handoff must print once:\n%s", output)
	}
	if strings.Count(output, "session refreshed") != 2 || !strings.Contains(output, "session expired") || !strings.Contains(output, "session changed") {
		t.Fatalf("recycle narration missing:\n%s", output)
	}
	if !strings.Contains(output, "relay stopped") || errOut.Len() != 0 {
		t.Fatalf("unexpected shutdown output:\n%s\n%s", output, errOut.String())
	}
}

func TestRelayLoopRetriesConsoleOutagesAndStopsOnRejectedLogin(t *testing.T) {
	originalDelay := relayRetryDelayFor
	relayRetryDelayFor = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { relayRetryDelayFor = originalDelay })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	runtime := &scriptedRelayRuntime{steps: []func(context.Context, *aiproxy.Engine) error{
		func(context.Context, *aiproxy.Engine) error {
			return &url.Error{Op: "Post", URL: "https://console.example.test", Err: errors.New("connection refused")}
		},
		func(context.Context, *aiproxy.Engine) error {
			return &agentapi.Error{StatusCode: 503, Code: "unavailable", Retryable: true}
		},
		func(_ context.Context, engine *aiproxy.Engine) error {
			engine.OnStarted(relayTestEndpoints())
			return errors.New("backend connection reset")
		},
		func(_ context.Context, engine *aiproxy.Engine) error {
			engine.OnStarted(relayTestEndpoints())
			cancel()
			return nil
		},
	}}
	if err := runRelayLoop(ctx, strings.NewReader(""), &out, &errOut, runtime, aiproxy.New()); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 4 || strings.Count(errOut.String(), "Retrying in") != 3 {
		t.Fatalf("outages were not retried: calls=%d\n%s", runtime.calls, errOut.String())
	}

	rejected := &scriptedRelayRuntime{steps: []func(context.Context, *aiproxy.Engine) error{
		func(context.Context, *aiproxy.Engine) error { return airuntime.ErrAuthenticationRequired },
	}}
	if err := runRelayLoop(context.Background(), strings.NewReader(""), &out, &errOut, rejected, aiproxy.New()); !errors.Is(err, airuntime.ErrAuthenticationRequired) {
		t.Fatalf("rejected login must stop the relay: %v", err)
	}
	misconfigured := &scriptedRelayRuntime{steps: []func(context.Context, *aiproxy.Engine) error{
		func(context.Context, *aiproxy.Engine) error {
			return errors.New("listen for Phase AI HTTP proxy: address already in use")
		},
	}}
	if err := runRelayLoop(context.Background(), strings.NewReader(""), &out, &errOut, misconfigured, aiproxy.New()); err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("configuration errors before the first start must surface: %v", err)
	}
	if relayRetryDelay(0) != time.Second || relayRetryDelay(3) != 8*time.Second || relayRetryDelay(10) != relayMaxRetryDelay {
		t.Fatal("unexpected retry backoff")
	}
}
