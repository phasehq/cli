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
	"runtime"
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
	lookPath func(file string) (string, error)
}

func (r *recordingTrustRunner) LookPath(file string) (string, error) {
	if r.lookPath != nil {
		return r.lookPath(file)
	}
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
	inspectionArgs := strings.Join(runner.commands[0].Args, " ")
	for _, required := range []string{"Cert:\\CurrentUser\\Root", "CN=Phase AI Proxy CA", "O=Phase", "Subject -eq $_.Issuer", "2.5.29.19", "PHASE_CA_OBSOLETE"} {
		if !strings.Contains(inspectionArgs, required) {
			t.Fatalf("Windows inspection is not scoped to Phase-owned current-user roots; missing %q in %s", required, inspectionArgs)
		}
	}
	// The Cert: drive refuses Root store removals under -NonInteractive.
	if strings.Contains(inspectionArgs, "Remove-Item") {
		t.Fatalf("Windows inspection must not delete through the Cert: drive: %s", inspectionArgs)
	}
}

func TestUserCATrustWindowsRemovesObsoletePhaseRootsWithCertutilBeforeTrusting(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	obsolete := []string{strings.Repeat("A1", 20), strings.Repeat("0F", 20)}
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-NoLogo" {
			return []byte("PHASE_CA_OBSOLETE " + obsolete[0] + "\r\nPHASE_CA_OBSOLETE " + obsolete[1] + "\r\n"), nil
		}
		return nil, nil
	}}
	result, err := (userCATrustInstaller{GOOS: "windows", Home: `C:\\Users\\phase`, Runner: runner}).Trust(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.AlreadyTrusted || len(runner.commands) != 4 {
		t.Fatalf("unexpected result=%+v commands=%v", result, runner.commands)
	}
	for index, thumbprint := range obsolete {
		command := runner.commands[index+1]
		want := []string{"-user", "-delstore", "Root", thumbprint}
		if command.Name != "/usr/bin/certutil" || !reflect.DeepEqual(command.Args, want) {
			t.Fatalf("removal %d = %s %v, want certutil %v", index, command.Name, command.Args, want)
		}
	}
	want := []string{"-user", "-addstore", "-f", "Root", certificatePath}
	if !reflect.DeepEqual(runner.commands[3].Args, want) {
		t.Fatalf("certutil args = %v, want %v", runner.commands[3].Args, want)
	}
}

func TestUserCATrustWindowsRejectsMalformedObsoleteThumbprint(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	// certutil -delstore also accepts store indexes: "0" is the first root.
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-NoLogo" {
			return []byte("PHASE_CA_OBSOLETE 0\r\n"), nil
		}
		return nil, nil
	}}
	_, err := (userCATrustInstaller{GOOS: "windows", Home: `C:\\Users\\phase`, Runner: runner}).Trust(certificatePath)
	if err == nil || len(runner.commands) != 1 {
		t.Fatalf("malformed thumbprint err=%v commands=%v", err, runner.commands)
	}
}

func TestUserCATrustWindowsStopsWhenObsoleteRootRemovalFails(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	runner := &recordingTrustRunner{run: func(_ string, args ...string) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "-NoLogo":
			return []byte("PHASE_CA_OBSOLETE " + strings.Repeat("AB", 20) + "\r\n"), nil
		case len(args) > 1 && args[1] == "-delstore":
			return []byte("CertUtil: -delstore command FAILED: 0x800704c7 (WIN32: 1223 ERROR_CANCELLED)"), errors.New("exit status 2")
		}
		return nil, nil
	}}
	_, err := (userCATrustInstaller{GOOS: "windows", Home: `C:\\Users\\phase`, Runner: runner}).Trust(certificatePath)
	if err == nil || !strings.Contains(err.Error(), "ERROR_CANCELLED") {
		t.Fatalf("removal failure err = %v", err)
	}
	for _, command := range runner.commands {
		if len(command.Args) > 1 && command.Args[1] == "-addstore" {
			t.Fatalf("new CA was added after an obsolete root could not be removed: %v", runner.commands)
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
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
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

func TestUserCATrustAvailabilityNamesTheMissingPackage(t *testing.T) {
	missing := func(string) (string, error) { return "", errors.New("not found") }
	osRelease := func(content string) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if path != "/etc/os-release" {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		}
	}
	for name, tc := range map[string]struct {
		goos    string
		release string
		want    string
	}{
		"fedora":         {"linux", "ID=fedora\nVERSION_ID=41\n", "package nss-tools"},
		"rocky via like": {"linux", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", "package nss-tools"},
		"mint via like":  {"linux", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", "package libnss3-tools"},
		"alpine":         {"linux", "ID=alpine\n", "package nss-tools"},
		"arch":           {"linux", "ID=arch\n", "package nss)"},
		"opensuse":       {"linux", "ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n", "package mozilla-nss-tools"},
		"unknown":        {"linux", "ID=somethingelse\n", "libnss3-tools on Debian/Ubuntu"},
		"no os-release":  {"linux", "", "libnss3-tools on Debian/Ubuntu"},
		"darwin":         {"darwin", "", "macOS security tool"},
		"windows":        {"windows", "", "Windows powershell.exe"},
	} {
		t.Run(name, func(t *testing.T) {
			installer := userCATrustInstaller{GOOS: tc.goos, Runner: &recordingTrustRunner{lookPath: missing}, ReadFile: osRelease(tc.release)}
			if tc.release == "" {
				installer.ReadFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
			}
			err := installer.withDefaults().availability()
			if !errors.Is(err, ErrUserCATrustToolMissing) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("availability = %v, want ErrUserCATrustToolMissing mentioning %q", err, tc.want)
			}
			if hint := UserCATrustToolHint(err); strings.HasPrefix(hint, ErrUserCATrustToolMissing.Error()) || !strings.Contains(hint, tc.want) {
				t.Fatalf("hint = %q", hint)
			}
		})
	}
	present := userCATrustInstaller{GOOS: "linux", Runner: &recordingTrustRunner{}}.withDefaults()
	if err := present.availability(); err != nil {
		t.Fatalf("certutil present reported %v", err)
	}
	if err := (userCATrustInstaller{GOOS: "plan9", Runner: &recordingTrustRunner{}}).withDefaults().availability(); !errors.Is(err, ErrUserCATrustUnsupported) {
		t.Fatalf("unsupported platform = %v", err)
	}
}

func TestUserCATrustLinuxMissingCertutilIsAMissingToolError(t *testing.T) {
	certificatePath, _, _ := writeTrustTestCA(t)
	runner := &recordingTrustRunner{lookPath: func(string) (string, error) { return "", errors.New("not found") }}
	installer := userCATrustInstaller{GOOS: "linux", Home: t.TempDir(), Runner: runner, ReadFile: func(path string) ([]byte, error) {
		if path == "/etc/os-release" {
			return []byte("ID=debian\n"), nil
		}
		return os.ReadFile(path)
	}}
	_, err := installer.Trust(certificatePath)
	if !errors.Is(err, ErrUserCATrustToolMissing) || !strings.Contains(err.Error(), "libnss3-tools") {
		t.Fatalf("missing certutil error = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands ran without certutil: %v", runner.commands)
	}
}

func TestWindowsPowerShellEnvironmentReplacesTheInheritedModulePath(t *testing.T) {
	environment := windowsPowerShellEnvironment([]string{`PATH=C:\bin`, `PSModulePath=C:\Program Files\PowerShell\7\Modules`, `HOME=C:\Users\phase`})
	var modulePaths []string
	for _, entry := range environment {
		if strings.HasPrefix(strings.ToLower(entry), "psmodulepath=") {
			modulePaths = append(modulePaths, entry)
		}
	}
	if len(modulePaths) != 1 || !strings.Contains(modulePaths[0], `\WindowsPowerShell\v1.0\Modules`) || strings.Contains(modulePaths[0], `PowerShell\7`) {
		t.Fatalf("module path = %v", modulePaths)
	}
	if len(environment) != 3 {
		t.Fatalf("environment = %v", environment)
	}
}
