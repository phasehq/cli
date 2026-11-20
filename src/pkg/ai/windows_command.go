package ai

import "strings"

// shortPathName resolves a path's 8.3 short name; tests replace it.
var shortPathName = windowsShortPathName

// WindowsShellCommand renders the WindowsPlainCommand form, or PowerShell's
// call-operator form when there is none.
func WindowsShellCommand(arguments []string) string {
	if line, ok := WindowsPlainCommand(arguments); ok {
		return line
	}
	return PowerShellCallCommand(arguments)
}

// WindowsPlainCommand renders the one form PowerShell, cmd and Git Bash all
// run: an unquoted forward-slash path, or its 8.3 name, and plain words. It
// reports false when a word still needs quoting.
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

// PowerShellCallCommand renders `& 'exe' 'arg' ...`. PowerShell treats the
// typographic single quotes as quote characters too, so each is doubled.
func PowerShellCallCommand(arguments []string) string {
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = "'" + powerShellQuoteEscape(argument) + "'"
	}
	return "& " + strings.Join(quoted, " ")
}

func powerShellQuoteEscape(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character == '\'' || character == '\u2018' || character == '\u2019' || character == '\u201A' || character == '\u201B' {
			builder.WriteRune(character)
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

// windowsExecutableForms lists the spellings of executable in a rendered command.
func windowsExecutableForms(executable string) []string {
	forms := []string{executable, strings.ReplaceAll(executable, `\`, "/"), powerShellQuoteEscape(executable)}
	if short, err := shortPathName(executable); err == nil {
		forms = append(forms, strings.ReplaceAll(short, `\`, "/"))
	}
	return forms
}

// windowsShellPlainWord reports a word every shell passes through unchanged.
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
