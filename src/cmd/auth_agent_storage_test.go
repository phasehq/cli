package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
	gokeyring "github.com/zalando/go-keyring"
)

func TestStoreLoginTokenNeedsAKeystoreUnlessInsecureStorageIsChosen(t *testing.T) {
	works := func(string, string) error { return nil }
	broken := func(string, string) error { return errors.New("no secret service") }

	if inConfig, err := storeLoginToken(works, "agent-1", "token", false); err != nil || inConfig {
		t.Fatalf("working keystore: inConfig=%v err=%v", inConfig, err)
	}
	if inConfig, err := storeLoginToken(works, "agent-1", "token", true); err != nil || inConfig {
		t.Fatalf("the flag must not skip a working keystore: inConfig=%v err=%v", inConfig, err)
	}
	inConfig, err := storeLoginToken(broken, "agent-1", "token", false)
	if err == nil || inConfig || !strings.Contains(err.Error(), "--insecure-storage") {
		t.Fatalf("no keystore must fail and name the flag: inConfig=%v err=%v", inConfig, err)
	}
	if inConfig, err := storeLoginToken(broken, "agent-1", "token", true); err != nil || !inConfig {
		t.Fatalf("chosen plain-text storage: inConfig=%v err=%v", inConfig, err)
	}
}

// A personal or service login never falls back to the config file on its own:
// a failed keystore write fails the login and leaves no token on disk.
func TestSaveUserLoginRefusesPlainTextWithoutTheFlag(t *testing.T) {
	isolateAgentCommand(t, "https://console.phase.invalid")
	t.Cleanup(gokeyring.MockInit)
	gokeyring.MockInitWithError(errors.New("secret service unreachable"))
	login := config.UserConfig{Host: "https://console.phase.invalid", ID: "user-1"}

	cmd := &cobra.Command{}
	cmd.Flags().Bool("insecure-storage", false, "")
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	err := saveUserLogin(cmd, login, "pss_user:v1:fake-token")
	if err == nil || !strings.Contains(err.Error(), "--insecure-storage") {
		t.Fatalf("err = %v, want the login refused naming --insecure-storage", err)
	}
	if data, readErr := os.ReadFile(config.ConfigFilePath); readErr == nil && strings.Contains(string(data), "fake-token") {
		t.Fatal("the token was written to the config file")
	}

	if err := cmd.Flags().Set("insecure-storage", "true"); err != nil {
		t.Fatal(err)
	}
	if err := saveUserLogin(cmd, login, "pss_user:v1:fake-token"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(config.ConfigFilePath)
	if err != nil || !strings.Contains(string(data), "fake-token") {
		t.Fatalf("chosen plain-text storage did not save the token: %v", err)
	}
	if !strings.Contains(stderr.String(), "plain text") {
		t.Fatalf("stderr = %q, want a plain-text warning", stderr.String())
	}
}
