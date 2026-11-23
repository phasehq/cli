package owner

import "strings"

// Tool is how one AI coding tool's processes are recognised. The table is plain data,
// so a server can supply it later.
type Tool struct {
	Name string `json:"name"`
	// Match lists the ways to recognise it. Any one is enough.
	Match []Match `json:"match"`
}

// Match is one way to recognise a tool, from the executable it was started from.
// Every field that is set has to hold, and names and paths are compared exactly as
// written. A Match that says nothing about the executable recognises nothing: a
// script alone is never enough.
type Match struct {
	// File is the executable's file name.
	File string `json:"file,omitempty"`
	// FilePrefix is how the executable's file name starts.
	FilePrefix string `json:"filePrefix,omitempty"`
	// Path is a part of the executable's path.
	Path string `json:"path,omitempty"`
	// Package is the folder the tool is installed in, such as "@openai/codex". It's
	// for a tool that runs as a script, where the executable is only the runtime,
	// such as node: one of the arguments has to be a path that goes through that
	// folder. An argument that only mentions the name is no such path, and any
	// program can be given one.
	Package string `json:"package,omitempty"`
}

// Tools is the table Identify uses. The first tool that matches wins.
//
// The chat apps aren't here: Claude.app and ChatGPT.app are their own programs, and
// only the coding tools they ship are matched, by those tools' own executables.
var Tools = []Tool{
	{Name: "claude", Match: []Match{
		{File: "claude"},
		// The installer keeps each release in a file named after its version.
		{Path: "/claude/versions/"},
		{File: "node", Package: "@anthropic-ai/claude-code"},
		{File: "bun", Package: "@anthropic-ai/claude-code"},
	}},
	{Name: "codex", Match: []Match{
		{File: "codex"},
		// Its package keeps a binary for each platform, named after the platform.
		// Outside the package, a name that starts the same is some other program.
		{FilePrefix: "codex-", Path: "/@openai/codex/"},
		{File: "node", Package: "@openai/codex"},
	}},
	{Name: "opencode", Match: []Match{
		{File: "opencode"},
		{File: "node", Package: "opencode-ai"},
		{File: "bun", Package: "opencode-ai"},
	}},
	{Name: "cursor", Match: []Match{
		{Path: "/Cursor.app/"},
		// Its command-line agent runs as the copy of node kept beside each release.
		{File: "node", Path: "/cursor-agent/"},
	}},
}

// Identify names the tool a process is, or returns "" when it isn't one.
func Identify(process Process) string {
	return IdentifyWith(Tools, process)
}

// IdentifyWith is Identify with another table.
func IdentifyWith(tools []Tool, process Process) string {
	if process.Executable == "" {
		return ""
	}
	for _, tool := range tools {
		for _, match := range tool.Match {
			if match.holds(process) {
				return tool.Name
			}
		}
	}
	return ""
}

func (m Match) holds(process Process) bool {
	if m.File == "" && m.FilePrefix == "" && m.Path == "" {
		return false
	}
	file := process.Executable[strings.LastIndexByte(process.Executable, '/')+1:]
	if m.File != "" && file != m.File {
		return false
	}
	if m.FilePrefix != "" && !strings.HasPrefix(file, m.FilePrefix) {
		return false
	}
	if m.Path != "" && !strings.Contains(process.Executable, m.Path) {
		return false
	}
	if folder := strings.Trim(m.Package, "/"); folder != "" {
		for _, argument := range process.Args {
			if strings.Contains(argument, "/"+folder+"/") {
				return true
			}
		}
		return false
	}
	return true
}
