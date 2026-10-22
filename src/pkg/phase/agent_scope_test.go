package phase

import (
	"strings"
	"testing"
)

func TestNewPhaseRejectsAgentTokenForLegacyAPIs(t *testing.T) {
	token := "pss_agent:v1:" + strings.Repeat("a", 64)
	_, err := NewPhase(false, token, "https://console.phase.dev")
	if err == nil || !strings.Contains(err.Error(), "phase ai") {
		t.Fatalf("expected clear Agent scope error, got %v", err)
	}
}

func TestNewPhaseRejectsAgentTokenFromEnvironment(t *testing.T) {
	t.Setenv("PHASE_SERVICE_TOKEN", "pss_agent:v1:"+strings.Repeat("a", 64))
	_, err := NewPhase(true, "", "")
	if err == nil || !strings.Contains(err.Error(), "phase ai") {
		t.Fatalf("expected clear Agent scope error, got %v", err)
	}
}
