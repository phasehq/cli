package cmd

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/phasehq/cli/pkg/config"
)

func terminalSafeIdentityText(value, fallback string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func organizationDisplayName(user config.UserConfig) string {
	if user.OrganizationName != nil {
		return terminalSafeIdentityText(*user.OrganizationName, "N/A")
	}
	return "N/A"
}

func agentDisplayName(user config.UserConfig) string {
	return terminalSafeIdentityText(user.PrincipalName, "AI Agent")
}

func agentPrincipalID(user config.UserConfig) string {
	return terminalSafeIdentityText(user.PrincipalID, "N/A")
}

func agentWorkflowDisplay(user config.UserConfig) string {
	return terminalSafeIdentityText(user.WorkflowName, "N/A")
}

func writeWhoami(w io.Writer, user config.UserConfig) {
	if user.IsAgentPrincipal() {
		fmt.Fprintln(w, "🤖 Identity: AI Agent")
		fmt.Fprintf(w, "🤖 Agent: %s\n", agentDisplayName(user))
		fmt.Fprintf(w, "🆔 Agent ID: %s\n", agentPrincipalID(user))
		fmt.Fprintf(w, "🔀 Workflow: %s\n", agentWorkflowDisplay(user))
		fmt.Fprintf(w, "🏢 Organization: %s\n", organizationDisplayName(user))
		fmt.Fprintf(w, "☁️\u200A Host: %s\n", terminalSafeIdentityText(user.Host, "N/A"))
		return
	}

	email := user.Email
	if email == "" {
		email = "N/A (Service Account)"
	}
	fmt.Fprintf(w, "✉️\u200A Email: %s\n", terminalSafeIdentityText(email, "N/A"))
	fmt.Fprintf(w, "🙋 Account ID: %s\n", terminalSafeIdentityText(user.ID, "N/A"))
	fmt.Fprintf(w, "🏢 Organization: %s\n", organizationDisplayName(user))
	fmt.Fprintf(w, "☁️\u200A Host: %s\n", terminalSafeIdentityText(user.Host, "N/A"))
}

func switchUserLabel(user config.UserConfig, current bool) string {
	shortID := terminalSafeIdentityText(user.ID, "N/A")
	if user.IsAgentPrincipal() && user.PrincipalID != "" {
		shortID = agentPrincipalID(user)
	}
	shortIDRunes := []rune(shortID)
	if len(shortIDRunes) > 8 {
		shortID = string(shortIDRunes[:8])
	}
	marker := ""
	if current {
		marker = " (current)"
	}

	if user.IsAgentPrincipal() {
		return fmt.Sprintf(
			"🏢 %s, 🤖 AI Agent: %s, 🔀 %s, ☁️  %s, 🆔 %s%s",
			organizationDisplayName(user),
			agentDisplayName(user),
			agentWorkflowDisplay(user),
			terminalSafeIdentityText(user.Host, "N/A"),
			shortID,
			marker,
		)
	}

	email := "Service Account"
	if user.Email != "" {
		email = terminalSafeIdentityText(user.Email, "N/A")
	}
	return fmt.Sprintf(
		"🏢 %s, ✉️  %s, ☁️  %s, 🆔 %s%s",
		organizationDisplayName(user), email, terminalSafeIdentityText(user.Host, "N/A"), shortID, marker,
	)
}

func switchedUserMessage(user config.UserConfig) string {
	if user.IsAgentPrincipal() {
		return fmt.Sprintf(
			"Switched to AI Agent 🤖: %s / %s (%s)",
			agentDisplayName(user),
			agentWorkflowDisplay(user),
			organizationDisplayName(user),
		)
	}
	email := "Service Account"
	if user.Email != "" {
		email = terminalSafeIdentityText(user.Email, "N/A")
	}
	return fmt.Sprintf("Switched to account 🙋: %s (%s)", email, organizationDisplayName(user))
}
