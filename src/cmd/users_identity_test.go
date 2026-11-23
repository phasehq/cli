package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/config"
)

func stringPointer(value string) *string { return &value }

func TestAgentUserConfigPersistsResolvedIdentity(t *testing.T) {
	identity := &agentapi.AgentIdentity{
		SchemaVersion: 1,
		PrincipalType: "agent",
		Agent:         agentapi.IdentityResource{ID: "agent-uuid", Name: "Claude"},
		Workflow:      agentapi.IdentityResource{ID: "workflow-uuid", Name: "Default"},
		Organization:  agentapi.IdentityResource{ID: "org-uuid", Name: "Phase"},
	}
	user := agentUserConfig("https://console.phase.dev", "agent-local-login", identity)
	if user.PrincipalType != config.PrincipalAgent || user.PrincipalID != "agent-uuid" ||
		user.PrincipalName != "Claude" || user.WorkflowID != "workflow-uuid" ||
		user.WorkflowName != "Default" || user.OrganizationID == nil ||
		*user.OrganizationID != "org-uuid" || user.OrganizationName == nil ||
		*user.OrganizationName != "Phase" {
		t.Fatalf("Agent identity metadata was not persisted: %+v", user)
	}
}

func TestAgentIdentityDisplaysDistinctly(t *testing.T) {
	user := config.UserConfig{
		Host:             "https://console.phase.dev",
		ID:               "agent-local-login",
		PrincipalType:    config.PrincipalAgent,
		PrincipalID:      "agent-uuid",
		PrincipalName:    "Claude",
		WorkflowName:     "Default",
		OrganizationName: stringPointer("Phase"),
	}
	var output bytes.Buffer
	writeWhoami(&output, user)
	for _, expected := range []string{
		"Identity: AI Agent",
		"Agent: Claude",
		"Agent ID: agent-uuid",
		"Workflow: Default",
		"Organization: Phase",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("whoami output %q does not contain %q", output.String(), expected)
		}
	}
	if strings.Contains(output.String(), "Service Account") || strings.Contains(output.String(), "Email:") {
		t.Fatalf("Agent was mislabeled as an account with email: %q", output.String())
	}

	label := switchUserLabel(user, true)
	if !strings.Contains(label, "AI Agent: Claude") || !strings.Contains(label, "Default") ||
		!strings.Contains(label, "Phase") || !strings.Contains(label, "(current)") {
		t.Fatalf("unexpected Agent switch label: %q", label)
	}
	message := switchedUserMessage(user)
	if message != "Switched to AI Agent 🤖: Claude / Default (Phase)" {
		t.Fatalf("unexpected Agent switch message: %q", message)
	}
}

func TestAgentIdentityDisplayStripsTerminalControlSequences(t *testing.T) {
	user := config.UserConfig{
		Host:             "https://console.phase.dev\x1b]52;c;host\x07",
		ID:               "agent-local-login",
		PrincipalType:    config.PrincipalAgent,
		PrincipalID:      "agent-uuid\x1b[31m",
		PrincipalName:    "Claude\x1b]52;c;clipboard\x07\nInjected",
		WorkflowName:     "Default\u202eWorkflow",
		OrganizationName: stringPointer("Phase\x1b[2J"),
	}
	var output bytes.Buffer
	writeWhoami(&output, user)
	label := switchUserLabel(user, false)
	message := switchedUserMessage(user)
	for name, value := range map[string]string{
		"whoami":  output.String(),
		"label":   label,
		"message": message,
	} {
		if strings.ContainsAny(value, "\x1b\x07") || strings.ContainsRune(value, '\u202e') ||
			strings.Contains(value, "\nInjected") {
			t.Fatalf("%s retained terminal control content: %q", name, value)
		}
	}
}

func TestUserAndServiceAccountDisplayRemainsUnchanged(t *testing.T) {
	user := config.UserConfig{
		ID:               "user-123456789",
		Host:             "https://console.phase.dev",
		Email:            "user@example.com",
		OrganizationName: stringPointer("Phase"),
	}
	if got := switchUserLabel(user, false); got != "🏢 Phase, ✉️  user@example.com, ☁️  https://console.phase.dev, 🆔 user-123" {
		t.Fatalf("User label changed: %q", got)
	}
	service := config.UserConfig{
		ID:               "service-123456789",
		Host:             "https://console.phase.dev",
		OrganizationName: stringPointer("Phase"),
	}
	if got := switchUserLabel(service, false); !strings.Contains(got, "Service Account") || strings.Contains(got, "AI Agent") {
		t.Fatalf("Service Account label changed: %q", got)
	}
}
