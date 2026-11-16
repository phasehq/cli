package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
