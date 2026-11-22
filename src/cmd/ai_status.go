package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

var aiStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "📡 Show Phase AI setup and proxy health",
	Args:  cobra.NoArgs,
	RunE:  runAIStatus,
}

func init() {
	aiCmd.AddCommand(aiStatusCmd)
}

const aiStatusProxyTimeout = 2 * time.Second

func runAIStatus(cmd *cobra.Command, _ []string) error {
	_, _ = io.WriteString(cmd.OutOrStdout(), renderAIStatus(cmd.Context()))
	return nil
}

// renderAIStatus is credential-free: it reads local setup files and, when the
// hook-owned proxy is running, asks it for Connection states.
func renderAIStatus(ctx context.Context) string {
	var out strings.Builder
	cfg := config.LoadAIConfig()
	if cfg == nil || !cfg.Enabled {
		out.WriteString("Phase AI:    disabled (run phase ai enable)\n")
	} else {
		out.WriteString("Phase AI:    enabled, local proxy\n")
		if harnesses := cfg.ConfiguredHarnessIDs(); len(harnesses) > 0 {
			out.WriteString("Harnesses:   " + strings.Join(harnesses, ", ") + "\n")
		} else {
			out.WriteString("Harnesses:   none (explicit phase ai run/exec only)\n")
		}
	}
	if user, err := config.GetDefaultUser(); err == nil {
		switch {
		case user.IsAgentPrincipal():
			label := strings.TrimSpace(user.PrincipalName)
			if label == "" {
				label = "Agent token"
			}
			if workflow := strings.TrimSpace(user.WorkflowName); workflow != "" {
				label += ", Workflow " + workflow
			}
			out.WriteString("Login:       " + label + " @ " + user.Host + "\n")
		default:
			label := strings.TrimSpace(user.Email)
			if label == "" {
				label = user.ID
			}
			out.WriteString("Login:       " + label + " @ " + user.Host + "\n")
			workflow := ""
			if cfg != nil {
				workflow = strings.TrimSpace(cfg.DefaultWorkflowID)
			}
			if workflow == "" {
				workflow = "not set (pass --workflow or rerun phase ai enable --workflow)"
			}
			out.WriteString("Workflow:    " + workflow + "\n")
		}
	} else {
		out.WriteString("Login:       none (run phase auth)\n")
	}

	directory, dirErr := hookRuntimeDir()
	if dirErr == nil {
		health := inspectHookRuntime(directory)
		state, stateErr := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
		switch {
		case health.ready && stateErr == nil:
			since := ""
			if !state.StartedAt.IsZero() {
				since = ", up " + formatStatusDuration(time.Since(state.StartedAt))
			}
			out.WriteString(fmt.Sprintf("Proxy:       running (pid %d%s)\n", state.PID, since))
			proxyStatus := aiProxyStatus(ctx, state.ProxyURL)
			var connections []remoteapi.StatusConnection
			if proxyStatus != nil {
				connections = proxyStatus.Connections
				if connections == nil {
					connections = []remoteapi.StatusConnection{}
				}
			}
			if connections == nil {
				for _, connection := range health.connections {
					connections = append(connections, remoteapi.StatusConnection{ConnectionID: connection.ConnectionID, Name: connection.Name, ServiceType: connection.ServiceType, Protocol: connection.Protocol})
				}
			}
			if len(connections) == 0 {
				out.WriteString("Connections: none yet\n")
			}
			for index, connection := range connections {
				label := strings.TrimSpace(connection.Name)
				if label == "" {
					label = connection.ConnectionID
				}
				line := label + " (" + connection.ServiceType + ")"
				if connection.State != "" {
					line += ": " + connection.State
				}
				if scope := appScopeSummary(connection.AppScope); scope != "" {
					line += "; " + scope
				}
				if index == 0 {
					out.WriteString("Connections: " + line + "\n")
				} else {
					out.WriteString("             " + line + "\n")
				}
			}
			if proxyStatus != nil && proxyStatus.LeakProtection != nil {
				out.WriteString("Leaks:       " + leakProtectionSummary(*proxyStatus.LeakProtection) + "\n")
			}
			if refreshedAt, reason := lastSessionRefresh(directory, time.Now(), 24*time.Hour); !refreshedAt.IsZero() {
				why := "scheduled renewal"
				if reason == "environment_changed" {
					why = "Connections or credentials changed in the Console"
				}
				out.WriteString("Refreshed:   " + refreshedAt.UTC().Format("2006-01-02 15:04:05Z") + " (" + why + ")\n")
			}
		case health.starting:
			out.WriteString("Proxy:       starting\n")
		case health.reason == "authentication":
			out.WriteString("Proxy:       stopped; the saved login was rejected (run phase auth --mode token)\n")
		default:
			out.WriteString("Proxy:       not running (starts on the next harness prompt or phase ai exec)\n")
		}
		var status runtimeEnvironmentStatus
		if readOwnerOnlyJSON(runtimeEnvironmentStatusPath(directory), &status) == nil {
			routing := "proxy routing retired"
			if status.ProxyLive && status.PID > 0 && processIsAlive(status.PID) {
				routing = "proxy routing active"
			}
			out.WriteString("Environment: " + runtimeEnvironmentPath(directory) + " (" + routing + ")\n")
		}
		if aiCAStore.KeystoreAvailable() {
			out.WriteString("CA:          " + describeCACertificate(filepath.Join(directory, "ca.pem")) + "\n")
		} else {
			out.WriteString("CA:          " + phaseproxy.NoKeystoreNotice + "\n")
		}
	}
	if cfg != nil {
		if paths := cfg.ConfiguredSkillInstallPaths(); len(paths) > 0 {
			out.WriteString("Skills:      " + strings.Join(paths, ", ") + "\n")
		}
	}
	return out.String()
}

// appScopeSummary describes an app Connection in one line: the app, its
// environments and what each class of secrets call does now, for example
// "orders-service (Development, Staging): read, create until 12:00Z allowed;
// update, delete ask".
func appScopeSummary(scope remoteapi.AppScope) string {
	if scope.App == nil {
		return ""
	}
	names := make([]string, 0, len(scope.Environments))
	for _, environment := range scope.Environments {
		names = append(names, environment.Name)
	}
	summary := scope.App.Name + " (" + strings.Join(names, ", ") + ")"
	byEffect := map[string][]string{}
	for _, class := range []string{agentapi.ClassRead, agentapi.ClassCreate, agentapi.ClassUpdate, agentapi.ClassDelete} {
		for key, access := range scope.Access {
			if string(key) != class {
				continue
			}
			name := class
			if access.Until != nil {
				name += " until " + access.Until.UTC().Format("2006-01-02 15:04Z")
			}
			byEffect[string(access.Effect)] = append(byEffect[string(access.Effect)], name)
		}
	}
	var effects []string
	for _, effect := range [][2]string{{agentapi.PolicyAllow, "allowed"}, {agentapi.PolicyAsk, "ask"}, {agentapi.PolicyBlock, "blocked"}} {
		if classes := byEffect[effect[0]]; len(classes) > 0 {
			effects = append(effects, strings.Join(classes, ", ")+" "+effect[1])
		}
	}
	if len(effects) > 0 {
		summary += ": " + strings.Join(effects, "; ")
	}
	return summary
}

// leakProtectionSummary is the one status line about leak protection: the
// mode, how many secrets are known, how many could not be protected or were
// protected in part, how many
// pattern rules are not applied, and which listed hosts are not inspected,
// with why for a host that would be read otherwise. It never names a secret.
func leakProtectionSummary(status remoteapi.LeakProtectionStatus) string {
	var mode string
	switch status.Mode {
	case "observe":
		mode = "observe (secrets in model traffic are reported, not replaced)"
	case "off":
		mode = "off (model traffic is not inspected)"
	default:
		mode = "censor (secrets in model traffic are replaced with placeholders)"
	}
	line := fmt.Sprintf("%s; %d %s known", mode, status.SecretsKnown, plural(status.SecretsKnown, "secret", "secrets"))
	if status.Unprotected > 0 {
		line += fmt.Sprintf(", %d too short or plain to protect", status.Unprotected)
	}
	if status.Partial > 0 {
		line += fmt.Sprintf(", %d protected in part", status.Partial)
	}
	if status.Inventory != nil {
		line += "; " + leakInventorySummary(*status.Inventory)
	}
	if status.RulesSkipped > 0 {
		line += fmt.Sprintf("; %d pattern %s skipped", status.RulesSkipped, plural(status.RulesSkipped, "rule", "rules"))
	}
	if len(status.UnreadHosts) > 0 {
		hosts := make([]string, 0, len(status.UnreadHosts))
		for _, host := range status.UnreadHosts {
			if reasons := status.UnreadReasons[host]; len(reasons) > 0 {
				host += " (" + strings.Join(reasons, ", ") + ")"
			}
			hosts = append(hosts, host)
		}
		line += "; not inspected: " + strings.Join(hosts, ", ")
	}
	return line
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

func aiProxyStatus(ctx context.Context, rawProxyURL string) *remoteapi.StatusResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := phaseProxyHTTPClient(rawProxyURL)
	if err != nil {
		return nil
	}
	requestContext, cancel := context.WithTimeout(ctx, aiStatusProxyTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, phaseproxy.ControlURL+"/v1/status", nil)
	if err != nil {
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	var status remoteapi.StatusResponse
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status) != nil || !status.SafeToPrint {
		return nil
	}
	return &status
}

func describeCACertificate(path string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return "not created yet (phase ai enable creates it)"
	}
	block, _ := pem.Decode(payload)
	if block == nil {
		return path + " (unreadable)"
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return path + " (unreadable)"
	}
	remaining := time.Until(certificate.NotAfter)
	switch {
	case remaining <= 0:
		return path + ", expired (renews on the next proxy start; rerun phase ai enable to re-trust it)"
	case remaining <= 14*24*time.Hour:
		return fmt.Sprintf("%s, expires %s (renews on the next proxy start)", path, certificate.NotAfter.UTC().Format("2006-01-02"))
	default:
		return fmt.Sprintf("%s, expires %s", path, certificate.NotAfter.UTC().Format("2006-01-02"))
	}
}

func formatStatusDuration(value time.Duration) string {
	value = value.Round(time.Minute)
	switch {
	case value < time.Hour:
		return fmt.Sprintf("%dm", int(value.Minutes()))
	case value < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(value.Hours()), int(value.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(value.Hours())/24, int(value.Hours())%24)
	}
}
