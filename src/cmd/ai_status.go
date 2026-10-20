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
		out.WriteString("Phase AI:    enabled, " + cfg.ProxyMode + " proxy\n")
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

	directory, dirErr := claudeHookRuntimeDir()
	if dirErr == nil {
		health := inspectClaudeRuntime(directory)
		state, stateErr := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile))
		switch {
		case health.ready && stateErr == nil:
			since := ""
			if !state.StartedAt.IsZero() {
				since = ", up " + formatStatusDuration(time.Since(state.StartedAt))
			}
			out.WriteString(fmt.Sprintf("Proxy:       running (pid %d%s)\n", state.PID, since))
			connections := aiStatusConnections(ctx, state.ProxyURL)
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
				if index == 0 {
					out.WriteString("Connections: " + line + "\n")
				} else {
					out.WriteString("             " + line + "\n")
				}
			}
		case health.starting:
			out.WriteString("Proxy:       starting\n")
		case health.reason == "authentication":
			out.WriteString("Proxy:       stopped; the saved login was rejected (run phase auth --mode token)\n")
		default:
			out.WriteString("Proxy:       not running (starts on the next harness prompt or phase ai exec)\n")
		}
		var status claudeEnvironmentStatus
		if readOwnerOnlyJSON(claudeEnvironmentStatusPath(directory), &status) == nil {
			routing := "proxy routing retired"
			if status.ProxyLive && status.PID > 0 && processIsAlive(status.PID) {
				routing = "proxy routing active"
			}
			out.WriteString("Environment: " + claudeEnvironmentPath(directory) + " (" + routing + ")\n")
		}
		out.WriteString("CA:          " + describeCACertificate(filepath.Join(directory, "ca.pem")) + "\n")
	}
	if cfg != nil {
		if paths := cfg.ConfiguredSkillInstallPaths(); len(paths) > 0 {
			out.WriteString("Skills:      " + strings.Join(paths, ", ") + "\n")
		}
	}
	return out.String()
}

func aiStatusConnections(ctx context.Context, rawProxyURL string) []remoteapi.StatusConnection {
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := phaseProxyHTTPClient(rawProxyURL, true)
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
	if status.Connections == nil {
		return []remoteapi.StatusConnection{}
	}
	return status.Connections
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
