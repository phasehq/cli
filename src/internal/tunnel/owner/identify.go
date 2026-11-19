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
// written. A Match that says nothing about the executable recognises nothing: an
// argument alone is never enough.
type Match struct {
	// File is the executable's file name.
	File string `json:"file,omitempty"`
	// FilePrefix is how the executable's file name starts.
	FilePrefix string `json:"filePrefix,omitempty"`
	// Path is a part of the executable's path.
	Path string `json:"path,omitempty"`
	// Argument is a part of one of the arguments. It's for a tool that runs as a
	// script, where the executable is only the runtime, such as node.
	Argument string `json:"argument,omitempty"`
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
		{File: "node", Argument: "@anthropic-ai/claude-code"},
		{File: "bun", Argument: "@anthropic-ai/claude-code"},
	}},
	{Name: "codex", Match: []Match{
		{File: "codex"},
		{FilePrefix: "codex-"},
		{File: "node", Argument: "@openai/codex"},
	}},
	{Name: "opencode", Match: []Match{
		{File: "opencode"},
		{File: "node", Argument: "opencode-ai"},
		{File: "bun", Argument: "opencode-ai"},
	}},
	{Name: "cursor", Match: []Match{
		{Path: "/Cursor.app/"},
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
	if m.Argument != "" {
		for _, argument := range process.Args {
			if strings.Contains(argument, m.Argument) {
				return true
			}
		}
		return false
	}
	return true
}
