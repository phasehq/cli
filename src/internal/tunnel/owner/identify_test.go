package owner

import (
	"encoding/json"
	"testing"
)

func TestIdentify(t *testing.T) {
	const home = "/Users/someone"
	for _, test := range []struct {
		name       string
		executable string
		args       []string
		want       string
	}{
		// Paths seen on a Mac with the tools installed.
		{name: "Claude Code's link", executable: home + "/.local/bin/claude", want: "claude"},
		{name: "Claude Code's release, a file named after its version", executable: home + "/.local/share/claude/versions/2.1.316", args: []string{"claude"}, want: "claude"},
		{name: "Claude Code inside the Claude app's own folder", executable: home + "/Library/Application Support/Claude/claude-code/2.1.325/0a1b2c3d/claude.app/Contents/MacOS/claude", want: "claude"},
		{name: "Claude Code from npm, run by node", executable: "/opt/homebrew/bin/node", args: []string{"node", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, want: "claude"},
		{name: "Claude Code from npm, run by bun", executable: home + "/.bun/bin/bun", args: []string{"bun", home + "/.bun/install/global/node_modules/@anthropic-ai/claude-code/cli.js", "--print"}, want: "claude"},
		{name: "Codex inside the ChatGPT app", executable: "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex", want: "codex"},
		{name: "Codex from Homebrew", executable: "/opt/homebrew/bin/codex", want: "codex"},
		{name: "Codex's release binary", executable: "/opt/homebrew/lib/node_modules/@openai/codex/vendor/codex-aarch64-apple-darwin", want: "codex"},
		{name: "Codex from npm, run by node", executable: home + "/.local/bin/node", args: []string{"node", "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js"}, want: "codex"},
		{name: "OpenCode from Homebrew", executable: "/opt/homebrew/bin/opencode", want: "opencode"},
		{name: "OpenCode in the Cellar", executable: "/opt/homebrew/Cellar/opencode/2.0.25/bin/opencode", want: "opencode"},
		{name: "OpenCode from npm, run by node", executable: "/usr/local/bin/node", args: []string{"node", "/usr/local/lib/node_modules/opencode-ai/bin/opencode"}, want: "opencode"},
		{name: "OpenCode from npm, run by bun", executable: home + "/.bun/bin/bun", args: []string{"bun", "x", "opencode-ai@latest"}, want: "opencode"},
		{name: "Cursor's extension host", executable: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)", args: []string{"Cursor Helper (Plugin): extension-host [1-2]"}, want: "cursor"},
		{name: "Cursor in the user's Applications", executable: home + "/Applications/Cursor.app/Contents/MacOS/Cursor", want: "cursor"},
		{name: "a relative path", executable: "./claude", want: "claude"},
		{name: "a bare name", executable: "codex", want: "codex"},

		// The chat apps are their own programs, not the coding tools.
		{name: "the Claude app", executable: "/Applications/Claude.app/Contents/MacOS/Claude"},
		{name: "the Claude app's helper", executable: "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"},
		{name: "the Claude app's renderer", executable: "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)"},
		{name: "the ChatGPT app", executable: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"},
		// Everything else on the machine.
		{name: "Chrome", executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
		{name: "Chrome's network helper", executable: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/142.0.1/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", args: []string{"Google Chrome Helper", "--type=utility", "--utility-sub-type=network.mojom.NetworkService"}},
		{name: "Safari's networking process", executable: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"},
		{name: "Firefox", executable: "/Applications/Firefox.app/Contents/MacOS/firefox"},
		{name: "Arc", executable: "/Applications/Arc.app/Contents/MacOS/Arc"},
		{name: "curl", executable: "/usr/bin/curl", args: []string{"curl", "https://api.anthropic.com/v1/messages"}},
		{name: "curl asking about a tool", executable: "/usr/bin/curl", args: []string{"curl", "https://registry.npmjs.org/@anthropic-ai/claude-code"}},
		{name: "python", executable: "/usr/bin/python3", args: []string{"python3", "ask.py"}},
		{name: "an unrelated node script", executable: "/opt/homebrew/bin/node", args: []string{"node", "server.js"}},
		{name: "an unrelated bun script", executable: home + "/.bun/bin/bun", args: []string{"bun", "run", "dev"}},
		{name: "a node script whose title was rewritten", executable: "/opt/homebrew/bin/node", args: []string{"my-service", "", ""}},
		{name: "a different capital letter", executable: "/usr/local/bin/Claude"},
		{name: "a different capital letter in the path", executable: "/Applications/cursor.app/Contents/MacOS/Electron"},
		{name: "a name that only starts like a tool", executable: "/usr/local/bin/claudette"},
		{name: "a name that only ends like a tool", executable: "/usr/local/bin/notclaude"},
		{name: "a codex look-alike without the dash", executable: "/usr/local/bin/codexplorer"},
		{name: "a folder named like a tool", executable: "/Users/someone/claude/bin/server"},
		{name: "node itself, named like a runtime only", executable: "/opt/homebrew/bin/nodemon", args: []string{"nodemon", "@anthropic-ai/claude-code"}},
		{name: "nothing known about it"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Identify(Process{PID: 1, Executable: test.executable, Args: test.args}); got != test.want {
				t.Fatalf("%q %q is %q, want %q", test.executable, test.args, got, test.want)
			}
		})
	}
}

// The table is data a server can send, so a careless entry must not turn every
// program into a tool.
func TestATableEntryThatSaysNothingAboutTheExecutableMatchesNothing(t *testing.T) {
	var tools []Tool
	if err := json.Unmarshal([]byte(`[
		{"name": "empty", "match": [{}]},
		{"name": "argument-only", "match": [{"argument": "serve"}]},
		{"name": "none", "match": []},
		{"name": "real", "match": [{"file": "aider", "argument": "--model"}, {"filePrefix": "aider-"}, {"path": "/aider/bin/"}]}
	]`), &tools); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		process Process
		want    string
	}{
		{Process{Executable: "/usr/bin/curl", Args: []string{"curl", "serve"}}, ""},
		{Process{Executable: "/usr/local/bin/aider", Args: []string{"aider"}}, ""},
		{Process{Executable: "/usr/local/bin/aider", Args: []string{"aider", "--model=x"}}, "real"},
		{Process{Executable: "/usr/local/bin/aider-nightly"}, "real"},
		{Process{Executable: "/opt/aider/bin/python3.13"}, "real"},
	} {
		if got := IdentifyWith(tools, test.process); got != test.want {
			t.Errorf("%q %q is %q, want %q", test.process.Executable, test.process.Args, got, test.want)
		}
	}
	if got := Identify(Process{Executable: "/usr/local/bin/aider"}); got != "" {
		t.Errorf("the built-in table knows aider as %q", got)
	}
}
