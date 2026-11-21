package keyring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phasehq/cli/pkg/config"
	gokeyring "github.com/zalando/go-keyring"
)

// isolate gives the test its own keystore and login file, before either is
// read, with two saved logins and no token in the environment.
func isolate(t *testing.T) {
	t.Helper()
	gokeyring.MockInit()
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = previous })
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	t.Setenv("PHASE_HOST", "")
	saved, _ := json.Marshal(config.Config{DefaultUser: "account-a", PhaseUsers: []config.UserConfig{
		{Host: "https://a.test", ID: "account-a", Token: "token-of-a-in-the-file"},
		{Host: "https://b.test", ID: "account-b", Token: "token-of-b-in-the-file"},
	}})
	if err := os.WriteFile(config.ConfigFilePath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The token a command reads and the account it is said to be for are one
// account's: from the keystore, from the file, and from the environment.
func TestCredentialsNameTheAccountTheyWereReadFor(t *testing.T) {
	isolate(t)
	if token, err := GetCredentials(); err != nil || token != "token-of-a-in-the-file" || LastAccount() != "account-a" {
		t.Fatalf("%q for %q: %v", token, LastAccount(), err)
	}
	if err := SetCredentials("account-b", "token-of-b-in-the-keystore"); err != nil {
		t.Fatal(err)
	}
	if err := config.SetDefaultUser("account-b"); err != nil {
		t.Fatal(err)
	}
	if token, err := GetCredentials(); err != nil || token != "token-of-b-in-the-keystore" || LastAccount() != "account-b" {
		t.Fatalf("%q for %q: %v", token, LastAccount(), err)
	}
	t.Setenv("PHASE_SERVICE_TOKEN", "token-from-the-environment")
	if token, err := GetCredentials(); err != nil || token != "token-from-the-environment" || LastAccount() != "" {
		t.Fatalf("%q for %q: %v", token, LastAccount(), err)
	}
	// A token that could not be read is nobody's.
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	if err := os.Remove(config.ConfigFilePath); err != nil {
		t.Fatal(err)
	}
	if _, err := GetCredentials(); err == nil || LastAccount() != "" {
		t.Fatalf("no login file: %v, for %q", err, LastAccount())
	}
}

// One look gives the host, the token and the saved login of one account.
func TestActiveLoginIsOneAccounts(t *testing.T) {
	isolate(t)
	login, err := ActiveLogin()
	if err != nil || login.Token != "token-of-a-in-the-file" || login.Host != "https://a.test" || login.User == nil || login.User.ID != "account-a" {
		t.Fatalf("%+v %v", login, err)
	}
	if err := SetCredentials("account-a", "token-of-a-in-the-keystore"); err != nil {
		t.Fatal(err)
	}
	// A PHASE_HOST that names another host never gets the saved login's token.
	t.Setenv("PHASE_HOST", "https://override.test")
	if login, err = ActiveLogin(); err == nil || login.Token != "" || login.Host != "" || login.User != nil {
		t.Fatalf("another host was given the saved login: %+v %v", login, err)
	}
	// The same host, written another way, is the saved login's.
	t.Setenv("PHASE_HOST", "https://A.test/")
	if login, err = ActiveLogin(); err != nil || login.Token != "token-of-a-in-the-keystore" || login.Host != "https://a.test" || login.User.ID != "account-a" {
		t.Fatalf("%+v %v", login, err)
	}
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "token-from-the-environment")
	if login, err = ActiveLogin(); err != nil || login.Token != "token-from-the-environment" || login.Host != config.PhaseCloudAPIHost || login.User != nil {
		t.Fatalf("a token from the environment: %+v %v", login, err)
	}
	// A token from the environment follows PHASE_HOST wherever it points.
	t.Setenv("PHASE_HOST", "https://override.test")
	if login, err = ActiveLogin(); err != nil || login.Token != "token-from-the-environment" || login.Host != "https://override.test" || login.User != nil {
		t.Fatalf("a token from the environment with PHASE_HOST: %+v %v", login, err)
	}
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	if err := config.SetDefaultUser("account-b"); err != nil {
		t.Fatal(err)
	}
	if login, err = ActiveLogin(); err != nil || login.Token != "token-of-b-in-the-file" || login.Host != "https://b.test" || login.User.ID != "account-b" {
		t.Fatalf("after a switch: %+v %v", login, err)
	}
}
