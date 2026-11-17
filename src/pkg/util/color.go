package util

import (
	"syscall"

	"golang.org/x/term"
)

const (
	ansiReset       = "\033[0m"
	ansiBold        = "\033[1m"
	ansiBoldGreen   = "\033[1;32m"
	ansiBoldCyan    = "\033[1;36m"
	ansiBoldMagenta = "\033[1;35m"
	ansiBoldYellow  = "\033[1;33m"
	ansiBoldRed     = "\033[1;31m"
	ansiBoldWhite   = "\033[1;37m"
)

func stdoutIsTTY() bool {
	return term.IsTerminal(int(syscall.Stdout))
}

func stderrIsTTY() bool {
	return term.IsTerminal(int(syscall.Stderr))
}

// wrap applies ANSI codes around text if the given fd is a TTY.
func wrap(code, text string, isTTY bool) string {
	if !isTTY {
		return text
	}
	return code + text + ansiReset
}

// --- stdout helpers ---

func Bold(text string) string       { return wrap(ansiBold, text, stdoutIsTTY()) }
func BoldGreen(text string) string  { return wrap(ansiBoldGreen, text, stdoutIsTTY()) }
func BoldYellow(text string) string { return wrap(ansiBoldYellow, text, stdoutIsTTY()) }

// --- stderr helpers ---

func BoldErr(text string) string        { return wrap(ansiBold, text, stderrIsTTY()) }
func BoldGreenErr(text string) string   { return wrap(ansiBoldGreen, text, stderrIsTTY()) }
func BoldCyanErr(text string) string    { return wrap(ansiBoldCyan, text, stderrIsTTY()) }
func BoldMagentaErr(text string) string { return wrap(ansiBoldMagenta, text, stderrIsTTY()) }
func BoldYellowErr(text string) string  { return wrap(ansiBoldYellow, text, stderrIsTTY()) }
func BoldRedErr(text string) string     { return wrap(ansiBoldRed, text, stderrIsTTY()) }

// AnsiCodes returns the raw ANSI prefix/reset for use in tree rendering, etc.
// Returns empty strings when stdout is not a TTY.
func AnsiCodes() (bold, cyan, green, magenta, reset string) {
	if !stdoutIsTTY() {
		return "", "", "", "", ""
	}
	return ansiBold, "\033[36m", "\033[32m", "\033[35m", ansiReset
}
