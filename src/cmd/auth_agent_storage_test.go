package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestStoreAgentTokenNeedsAKeystoreUnlessInsecureStorageIsChosen(t *testing.T) {
	works := func(string, string) error { return nil }
	broken := func(string, string) error { return errors.New("no secret service") }

	if inConfig, err := storeAgentToken(works, "agent-1", "token", false); err != nil || inConfig {
		t.Fatalf("working keystore: inConfig=%v err=%v", inConfig, err)
	}
	if inConfig, err := storeAgentToken(works, "agent-1", "token", true); err != nil || inConfig {
		t.Fatalf("the flag must not skip a working keystore: inConfig=%v err=%v", inConfig, err)
	}
	inConfig, err := storeAgentToken(broken, "agent-1", "token", false)
	if err == nil || inConfig || !strings.Contains(err.Error(), "--insecure-storage") {
		t.Fatalf("no keystore must fail and name the flag: inConfig=%v err=%v", inConfig, err)
	}
	if inConfig, err := storeAgentToken(broken, "agent-1", "token", true); err != nil || !inConfig {
		t.Fatalf("chosen plain-text storage: inConfig=%v err=%v", inConfig, err)
	}
}
