package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

func TestExecSelectedConnectionUsesPrivateChildEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX child to inspect isolated environment")
	}
	var originalProxy, selectedProxy string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == "" {
			t.Error("runtime data was not fetched through authenticated proxy")
		}
		if r.URL.Path == phaseproxy.ManifestPath {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-one",
				"processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
					"PHASE_AI_ENABLED": "1", "HTTP_PROXY": originalProxy, "http_proxy": originalProxy,
					"HTTPS_PROXY": originalProxy, "https_proxy": originalProxy,
					"AWS_REGION": "default", "PGPASSWORD": "managed-postgres",
				}},
			})
			return
		}
		if r.URL.Path != "/v1/connections/aws-two/environment" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "connectionId": "aws-two", "configGeneration": 1, "processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
			"PHASE_AI_ENABLED": "1", "HTTP_PROXY": selectedProxy, "http_proxy": selectedProxy,
			"HTTPS_PROXY": selectedProxy, "https_proxy": selectedProxy,
			"AWS_REGION": "selected", "AWS_SECRET_ACCESS_KEY": "decoy-selected",
		}, Unset: []string{"AWS_PROFILE"}}})
	}))
	defer server.Close()
	proxy, _ := url.Parse(server.URL)
	proxy.User = url.UserPassword("phase", "test-capability")
	originalProxy = proxy.String()
	proxy.User = url.UserPassword("phase.aws-two", "test-capability")
	selectedProxy = proxy.String()
	t.Setenv("HTTPS_PROXY", originalProxy)
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("AWS_REGION", "parent")
	t.Setenv("AWS_PROFILE", "parent-profile")
	t.Setenv("PGPASSWORD", "managed-postgres")
	command := &cobra.Command{}
	command.SetContext(t.Context())
	command.Flags().String("connection", "aws-two", "")
	if err := runAIExecInheritedCommand(command, []string{"/bin/sh", "-c", `test "$AWS_REGION" = selected && test "$AWS_SECRET_ACCESS_KEY" = decoy-selected && test -z "$AWS_PROFILE" && test -z "$PGPASSWORD"`}); err != nil {
		t.Fatal(err)
	}
	if value := firstEnvironmentValue("AWS_REGION"); value != "parent" {
		t.Fatal("selected command mutated parent process environment")
	}
}

func TestExecSelectedConnectionKeepsInheritedTrustPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX child to inspect isolated environment")
	}
	// A relay plans its own CA paths; a bootstrapped sandbox holds the same
	// trust material at its own paths, or leaves a variable unset.
	const relayBundle = "/relay-home/.phase/ai/runtime-ca-bundle.pem"
	var originalProxy, selectedProxy string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy, password := originalProxy, "decoy-default"
		if r.URL.Path == "/v1/connections/pg-two/environment" {
			proxy, password = selectedProxy, "decoy-selected"
		} else if r.URL.Path != phaseproxy.ManifestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 1, "sessionUid": "session-one", "connectionId": "pg-two", "configGeneration": 1,
			"processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
				"PHASE_AI_ENABLED": "1", "HTTP_PROXY": proxy, "http_proxy": proxy, "HTTPS_PROXY": proxy, "https_proxy": proxy,
				"PGSSLROOTCERT": relayBundle, "SSL_CERT_FILE": relayBundle, "PGPASSWORD": password,
			}},
		})
	}))
	defer server.Close()
	proxy, _ := url.Parse(server.URL)
	proxy.User = url.UserPassword("phase", "test-capability")
	originalProxy = proxy.String()
	proxy.User = url.UserPassword("phase.pg-two", "test-capability")
	selectedProxy = proxy.String()
	sandboxBundle := filepath.Join(t.TempDir(), "ca-bundle.pem")
	t.Setenv("HTTPS_PROXY", originalProxy)
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("PGSSLROOTCERT", sandboxBundle)
	t.Setenv("PGPASSWORD", "decoy-default")
	t.Setenv("SSL_CERT_FILE", "")
	os.Unsetenv("SSL_CERT_FILE")
	command := &cobra.Command{}
	command.SetContext(t.Context())
	command.Flags().String("connection", "pg-two", "")
	if err := runAIExecInheritedCommand(command, []string{"/bin/sh", "-c",
		`test "$PGSSLROOTCERT" = "` + sandboxBundle + `" && test -z "${SSL_CERT_FILE+set}" && test "$PGPASSWORD" = decoy-selected`}); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedEnvironmentRejectsTokenOrProxySubstitution(t *testing.T) {
	for _, unsafe := range []string{"token", "proxy"} {
		t.Run(unsafe, func(t *testing.T) {
			var selectedProxy string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				values := map[string]string{
					"PHASE_AI_ENABLED": "1", "HTTP_PROXY": selectedProxy, "http_proxy": selectedProxy,
					"HTTPS_PROXY": selectedProxy, "https_proxy": selectedProxy,
				}
				if unsafe == "token" {
					values["PHASE_SERVICE_TOKEN"] = "not-a-real-token"
				} else {
					values["HTTP_PROXY"] = "http://phase:other@127.0.0.1:9999"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "connectionId": "aws-two", "configGeneration": 1, "processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: values}})
			}))
			defer server.Close()
			proxy, _ := url.Parse(server.URL)
			proxy.User = url.UserPassword("phase", "test-capability")
			ambientProxy := proxy.String()
			t.Setenv("HTTPS_PROXY", ambientProxy)
			proxy.User = url.UserPassword("phase.aws-two", "test-capability")
			selectedProxy = proxy.String()
			_, err := loadSelectedConnectionEnvironmentFromProxy(t.Context(), "aws-two", ambientProxy)
			if err == nil || strings.Contains(err.Error(), "not-a-real-token") {
				t.Fatal("unsafe selected environment was accepted or exposed")
			}
		})
	}
}
