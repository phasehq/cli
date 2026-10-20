package proxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type trustCommand struct {
	Name string
	Args []string
}

type recordingTrustRunner struct {
	commands []trustCommand
	run      func(name string, args ...string) ([]byte, error)
}

func (r *recordingTrustRunner) LookPath(file string) (string, error) {
	return "/usr/bin/" + file, nil
}

func (r *recordingTrustRunner) Run(name string, args ...string) ([]byte, error) {
	r.commands = append(r.commands, trustCommand{Name: name, Args: append([]string(nil), args...)})
	if r.run != nil {
		return r.run(name, args...)
	}
	return nil, nil
}

func writeTrustTestCA(t *testing.T) (string, []byte, *CA) {
	t.Helper()
	ca, certificatePEM, _, err := GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, certificatePEM, ca
}

func TestUserCATrustDarwinUsesOnlyCurrentUserKeychain(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	const keychain = "/Users/phase/Library/Keychains/custom.keychain-db"
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "default-keychain":
			return []byte(`"` + keychain + `"` + "\n"), nil
		case "find-certificate":
			return nil, errors.New("not found")
		default:
			return nil, nil
		}
	}}
	result, err := (userCATrustInstaller{GOOS: "darwin", Home: "/Users/phase", Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Store != "macOS current-user keychain" || result.AlreadyTrusted {
		t.Fatalf("unexpected result: %+v", result)
	}
	var add *trustCommand
	for index := range runner.commands {
		if len(runner.commands[index].Args) > 0 && runner.commands[index].Args[0] == "add-trusted-cert" {
			add = &runner.commands[index]
			break
		}
	}
	if add == nil {
		t.Fatal("security add-trusted-cert was not called")
	}
	if strings.Contains(" "+strings.Join(add.Args, " ")+" ", " -d ") {
		t.Fatalf("add-trusted-cert targeted the admin trust domain: %v", add.Args)
	}
	want := []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, certificatePath}
	if !reflect.DeepEqual(add.Args, want) {
		t.Fatalf("add-trusted-cert args = %v, want %v", add.Args, want)
	}
}

func TestUserCATrustDarwinDetectsExistingCertificate(t *testing.T) {
	certificatePath, certificatePEM, _ := writeTrustTestCA(t)
	_, obsoletePEM, _, err := GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if args[0] == "find-certificate" {
			return append(append([]byte(nil), obsoletePEM...), certificatePEM...), nil
		}
		return nil, nil
	}}
	result, err := (userCATrustInstaller{GOOS: "darwin", Home: "/Users/phase", Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !result.AlreadyTrusted {
		t.Fatal("existing current-user certificate was not detected")
	}
	for _, command := range runner.commands {
		if len(command.Args) > 0 && (command.Args[0] == "add-trusted-cert" || command.Args[0] == "delete-certificate") {
			t.Fatalf("already trusted fast path mutated the keychain: %v", command.Args)
		}
	}
}

func TestUserCATrustDarwinRemovesOnlyObsoletePhaseRootBeforeRotation(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	_, obsoletePEM, _, err := GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(obsoletePEM)
	obsolete, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(obsolete.Raw)
	wantFingerprint := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if args[0] == "find-certificate" {
			return obsoletePEM, nil
		}
		return nil, nil
	}}
	result, err := (userCATrustInstaller{GOOS: "darwin", Home: "/Users/phase", Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.AlreadyTrusted {
		t.Fatal("obsolete Phase root was treated as current")
	}
	var deleted, added bool
	for _, command := range runner.commands {
		if len(command.Args) == 0 {
			continue
		}
		switch command.Args[0] {
		case "delete-certificate":
			// Removing the obsolete certificate must not also remove its trust
			// setting (-t): that would raise a second macOS authorization
			// dialog. add-trusted-cert below is the only dialog users see.
			deleted = reflect.DeepEqual(command.Args[1:3], []string{"-Z", wantFingerprint})
			for _, argument := range command.Args {
				if argument == "-t" {
					t.Fatalf("delete-certificate must not modify trust settings: %v", command.Args)
				}
			}
		case "add-trusted-cert":
			added = true
		}
	}
	if !deleted || !added {
		t.Fatalf("rotation commands=%v", runner.commands)
	}
	clone := *obsolete
	clone.Subject.Organization = []string{"Unrelated"}
	if isPhaseOwnedRoot(&clone) {
		t.Fatal("an unrelated root sharing the common name was classified as Phase-owned")
	}
}

func TestUserCATrustWindowsUsesUserStore(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	runner := &recordingTrustRunner{}
	result, err := (userCATrustInstaller{GOOS: "windows", Home: `C:\\Users\\phase`, Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Store != "Windows current-user Root store" || len(runner.commands) != 2 {
		t.Fatalf("unexpected result=%+v commands=%v", result, runner.commands)
	}
	want := []string{"-user", "-addstore", "-f", "Root", certificatePath}
	if !reflect.DeepEqual(runner.commands[1].Args, want) {
		t.Fatalf("certutil args = %v, want %v", runner.commands[1].Args, want)
	}
	rotationArgs := strings.Join(runner.commands[0].Args, " ")
	for _, required := range []string{"Cert:\\CurrentUser\\Root", "CN=Phase AI Proxy CA", "O=Phase", "Subject -eq $_.Issuer", "2.5.29.19", "Remove-Item -LiteralPath"} {
		if !strings.Contains(rotationArgs, required) {
			t.Fatalf("Windows rotation is not scoped to Phase-owned current-user roots; missing %q in %s", required, rotationArgs)
		}
	}
}

func TestUserCATrustWindowsAlreadyTrustedFastPath(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-NoLogo" {
			return []byte("PHASE_CA_CURRENT\n"), nil
		}
		return nil, nil
	}}
	result, err := (userCATrustInstaller{GOOS: "windows", Home: `C:\\Users\\phase`, Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !result.AlreadyTrusted || len(runner.commands) != 1 {
		t.Fatalf("already-trusted fast path result=%+v commands=%v", result, runner.commands)
	}
}

func TestUserCATrustLinuxUsesPerUserNSSDatabase(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	home := t.TempDir()
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if args[0] == "-L" {
			return nil, errors.New("nickname not found")
		}
		return nil, nil
	}}
	result, err := (userCATrustInstaller{GOOS: "linux", Home: home, Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Store != "Linux current-user NSS database" {
		t.Fatalf("unexpected result: %+v", result)
	}
	database := "sql:" + filepath.Join(home, ".pki", "nssdb")
	wantCommands := [][]string{
		{"-N", "--empty-password", "-d", database},
		{"-L", "-d", database, "-n", phaseAITrustNickname, "-a"},
		{"-A", "-d", database, "-n", phaseAITrustNickname, "-t", "C,,", "-i", certificatePath},
	}
	if len(runner.commands) != len(wantCommands) {
		t.Fatalf("commands = %v, want %v", runner.commands, wantCommands)
	}
	for index, want := range wantCommands {
		if !reflect.DeepEqual(runner.commands[index].Args, want) {
			t.Fatalf("command %d args = %v, want %v", index, runner.commands[index].Args, want)
		}
	}
	info, err := os.Stat(filepath.Join(home, ".pki", "nssdb"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("NSS directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestUserCATrustRejectsUnsupportedOSAndPrivateMaterial(t *testing.T) {
	certificatePath, certificatePEM, _ := writeTrustTestCA(t)
	runner := &recordingTrustRunner{}
	_, err := (userCATrustInstaller{GOOS: "plan9", Home: t.TempDir(), Runner: runner}).Trust(certificatePath)
	if !errors.Is(err, ErrUserCATrustUnsupported) {
		t.Fatalf("unsupported error = %v", err)
	}

	_, _, privatePEM, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(t.TempDir(), "unsafe.pem")
	if err := os.WriteFile(unsafePath, append(certificatePEM, privatePEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = (userCATrustInstaller{GOOS: "darwin", Home: t.TempDir(), Runner: runner}).Trust(unsafePath)
	if err == nil || len(runner.commands) != 0 {
		t.Fatalf("private material reached trust command: err=%v commands=%v", err, runner.commands)
	}
}

func TestUserCATrustNoticeDescribesTheSystemDialog(t *testing.T) {
	if notice := UserCATrustNotice("darwin"); !strings.Contains(notice, "Touch ID") || !strings.Contains(notice, "once") || !strings.Contains(notice, "No sudo") {
		t.Fatalf("darwin notice = %q", notice)
	}
	if notice := UserCATrustNotice("windows"); !strings.Contains(notice, "user Root store") {
		t.Fatalf("windows notice = %q", notice)
	}
	if notice := UserCATrustNotice("linux"); notice != "" {
		t.Fatalf("linux must not announce a dialog: %q", notice)
	}
}
