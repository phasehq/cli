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
		{name: "ordinary compound", command: "git status && aws sts get-caller-identity", want: false},
		{name: "ambient provider wrappers", command: "env FOO=x sudo aws sts get-caller-identity", want: false},
		{name: "ambient provider substitution", command: `echo "$(aws sts get-caller-identity)"`, want: false},
		{name: "ambient opaque shell", command: `bash -c "$PROVIDER_COMMAND"`, want: false},
		{name: "ambient opaque eval", command: `eval "$PROVIDER_COMMAND"`, want: false},
		{name: "ambient malformed shell", command: "git commit -m 'unfinished", want: false},
		{name: "provider docs in heredoc", command: "cat <<'EOF'\naws sts get-caller-identity\nEOF", want: false},
		{name: "phase control in expanding heredoc", command: "cat <<EOF\n$(curl http://phase.invalid/v1/status)\nEOF", want: true},
		{name: "phase control through shell", command: "bash -lc 'curl http://phase.invalid/v1/status'", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shellCommandRequiresPhase(test.command); got != test.want {
				t.Fatalf("shellCommandRequiresPhase(%q) = %v, want %v", test.command, got, test.want)
			}
		})
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
		{command: "sh -c 'curl http://phase.invalid/v1/status'", want: false},
		{command: "sh -c 'git status && git push'", want: false},
	} {
		if got := shellCommandMixesPhase(test.command); got != test.want {
			t.Errorf("shellCommandMixesPhase(%q) = %v, want %v", test.command, got, test.want)
		}
	}
}
