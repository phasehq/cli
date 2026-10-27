package ai

import "strings"

// shortPathName resolves a path's 8.3 short name; tests replace it.
var shortPathName = windowsShortPathName

// WindowsShellCommand renders a command line that runs the same way in every
// shell a harness may use on Windows: PowerShell, cmd, Git Bash, or a direct
// CreateProcess. That is the WindowsPlainCommand form when there is one, and
// otherwise the PowerShell call-operator form, PowerShell being the default
// shell of the Windows harnesses.
func WindowsShellCommand(arguments []string) string {
	if line, ok := WindowsPlainCommand(arguments); ok {
		return line
	}
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = "'" + strings.ReplaceAll(argument, "'", "''") + "'"
	}
	return "& " + strings.Join(quoted, " ")
}

// WindowsPlainCommand renders the only command line form that PowerShell, cmd
// and Git Bash all parse as a command: an unquoted path with forward slashes
// followed by plain words. PowerShell reads a leading quoted string as an
// expression, and cmd and bash reject PowerShell's & call operator. A path with
// spaces or shell characters uses its 8.3 short name; it reports false when a
// word still needs quoting.
func WindowsPlainCommand(arguments []string) (string, bool) {
	words := append([]string{strings.ReplaceAll(arguments[0], `\`, "/")}, arguments[1:]...)
	if !windowsShellPlainWord(words[0]) {
		if short, err := shortPathName(arguments[0]); err == nil && windowsShellPlainWord(strings.ReplaceAll(short, `\`, "/")) {
			words[0] = strings.ReplaceAll(short, `\`, "/")
		}
	}
	for _, word := range words {
		if !windowsShellPlainWord(word) {
			return "", false
		}
	}
	return strings.Join(words, " "), true
}

// windowsExecutableForms lists the spellings of executable that a rendered
// command may contain, including the backslash form earlier builds quoted, so
// hook entries written before WindowsShellCommand are still recognized.
func windowsExecutableForms(executable string) []string {
	forms := []string{executable, strings.ReplaceAll(executable, `\`, "/")}
	if short, err := shortPathName(executable); err == nil {
		forms = append(forms, strings.ReplaceAll(short, `\`, "/"))
	}
	return forms
}

// windowsShellPlainWord reports a word that PowerShell, cmd, and POSIX shells
// all pass through unquoted and unexpanded.
func windowsShellPlainWord(word string) bool {
	if word == "" || word[0] == '~' {
		return false
	}
	for _, character := range word {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && !strings.ContainsRune(":/._-~", character) {
			return false
		}
	}
	return true
}
