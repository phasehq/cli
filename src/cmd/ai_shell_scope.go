package cmd

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const phaseShellRedirect = "\x00redirect"

// powerShellWebCmdlet matches PowerShell's web cmdlets and their aliases as
// whole words, not inside names such as "confirm" or "$irm".
var powerShellWebCmdlet = regexp.MustCompile(`(?i)(^|[\s;|&({=])(invoke-webrequest|invoke-restmethod|iwr|irm)($|[\s;|)}])`)

// shellCommandUsesPowerShellWeb reports a PowerShell web cmdlet in a command
// that names phase.invalid. Invoke-WebRequest and Invoke-RestMethod ignore
// HTTP(S)_PROXY in Windows PowerShell, so such a call can never reach the Phase
// proxy and only fails to resolve the host; hooks reject it and point the Agent
// at curl, which they route. The check spans the whole command so a URL held
// in a variable ($u = "http://phase.invalid/..."; irm $u) is caught too.
func shellCommandUsesPowerShellWeb(command string) bool {
	return strings.Contains(strings.ToLower(command), "phase.invalid") && powerShellWebCmdlet.MatchString(command)
}

type phaseShellWord struct {
	value   string
	control bool
}

// shellCommandRequiresPhase recognizes only explicit Phase control calls.
// Provider clients, Phase CLI commands, and ordinary shell commands remain
// visible to the harness's normal permission evaluation.
//
// This is not a general shell security parser. Arbitrary scripts, SDKs, aliases,
// build targets, and variable-expanded endpoints are outside its supported
// boundary and do not receive Phase material. Malformed or opaque shell payloads
// remain ambient; the hook must not claim commands it cannot identify.
func shellCommandRequiresPhase(command string) bool {
	command, heredocCommands, valid := phaseStripShellHeredocs(command)
	if !valid {
		return false
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	for _, heredocCommand := range heredocCommands {
		if shellCommandRequiresPhase(heredocCommand) {
			return true
		}
	}
	nested, valid := phaseShellSubcommands(command)
	if !valid {
		return false
	}
	for _, subcommand := range nested {
		if shellCommandRequiresPhase(subcommand) {
			return true
		}
	}
	words, valid := phaseTokenizeShell(command)
	if !valid {
		return false
	}
	segment := make([]string, 0, 8)
	for _, word := range words {
		if word.control {
			if phaseSimpleCommandRequiresPhase(segment) {
				return true
			}
			segment = segment[:0]
		} else {
			segment = append(segment, word.value)
		}
	}
	return phaseSimpleCommandRequiresPhase(segment)
}

// shellCommandMixesPhase reports command lines that would otherwise run both
// managed and ordinary top-level shell work inside one credential environment.
// Hooks reject these and ask the Agent to split them into separate tool calls.
func shellCommandMixesPhase(command string) bool {
	command, heredocCommands, valid := phaseStripShellHeredocs(command)
	if !valid {
		return false
	}
	command = strings.TrimSpace(command)
	nested, valid := phaseShellSubcommands(command)
	if command == "" || !valid {
		return false
	}
	hasManaged := false
	hasOrdinary := false
	for _, heredocCommand := range heredocCommands {
		if shellCommandMixesPhase(heredocCommand) {
			return true
		}
		if shellCommandRequiresPhase(heredocCommand) {
			hasManaged = true
		} else {
			hasOrdinary = true
		}
	}
	for _, subcommand := range nested {
		if shellCommandMixesPhase(subcommand) {
			return true
		}
		if shellCommandRequiresPhase(subcommand) {
			hasManaged = true
		} else if strings.TrimSpace(subcommand) != "" {
			hasOrdinary = true
		}
	}
	words, valid := phaseTokenizeShell(command)
	if !valid {
		return false
	}
	segment := make([]string, 0, 8)
	nestedMix := false
	classify := func() {
		if !phaseShellSegmentHasCommand(segment) {
			return
		}
		// A script handed to sh -c, eval, or a wrapper such as env must not
		// smuggle ordinary work alongside a Phase control call.
		if script, nested := phaseNestedShellScript(segment); nested && shellCommandMixesPhase(script) {
			nestedMix = true
		}
		if phaseSimpleCommandRequiresPhase(segment) {
			hasManaged = true
		} else {
			hasOrdinary = true
		}
	}
	for _, word := range words {
		if word.control {
			classify()
			segment = segment[:0]
		} else {
			segment = append(segment, word.value)
		}
	}
	classify()
	return nestedMix || (hasManaged && hasOrdinary)
}

type phaseHeredoc struct {
	delimiter string
	stripTabs bool
	quoted    bool
	shellBody bool
	body      []string
}

// phaseStripShellHeredocs removes inert data lines while returning content that
// the shell can execute. Unquoted heredocs expand command substitutions, and a
// shell reading stdin can execute the whole body. Keeping those paths separate
// avoids treating provider names in ordinary generated files as commands.
func phaseStripShellHeredocs(command string) (string, []string, bool) {
	lines := strings.Split(command, "\n")
	pending := make([]phaseHeredoc, 0, 1)
	executable := make([]string, 0, 1)
	var quote byte
	var output strings.Builder
	for index, line := range lines {
		if len(pending) == 0 {
			output.WriteString(line)
			found, nextQuote, valid := phaseHeredocsOnLine(line, quote)
			if !valid {
				return "", nil, false
			}
			quote = nextQuote
			shellBody := phaseLineExecutesHeredocBody(line)
			for foundIndex := range found {
				found[foundIndex].shellBody = shellBody
			}
			pending = append(pending, found...)
		} else {
			candidate := strings.TrimSuffix(line, "\r")
			if pending[0].stripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == pending[0].delimiter {
				body := strings.Join(pending[0].body, "\n")
				if pending[0].shellBody {
					executable = append(executable, body)
				} else if !pending[0].quoted {
					subcommands, valid := phaseShellSubcommands(body)
					if !valid {
						return "", nil, false
					}
					executable = append(executable, subcommands...)
				}
				pending = pending[1:]
			} else {
				pending[0].body = append(pending[0].body, line)
			}
		}
		if index+1 < len(lines) {
			output.WriteByte('\n')
		}
	}
	return output.String(), executable, len(pending) == 0 && quote == 0
}

func phaseHeredocsOnLine(line string, quote byte) ([]phaseHeredoc, byte, bool) {
	found := make([]phaseHeredoc, 0, 1)
	for index := 0; index < len(line); index++ {
		character := line[index]
		if character == '\\' {
			index++
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == '#' && (index == 0 || unicode.IsSpace(rune(line[index-1]))) {
			break
		}
		if character != '<' || index+1 >= len(line) || line[index+1] != '<' {
			continue
		}
		if phaseInsideShellArithmetic(line, index) {
			index++
			continue
		}
		if index+2 < len(line) && line[index+2] == '<' {
			index += 2 // here-string, not a heredoc body
			continue
		}
		cursor := index + 2
		stripTabs := cursor < len(line) && line[cursor] == '-'
		if stripTabs {
			cursor++
		}
		for cursor < len(line) && unicode.IsSpace(rune(line[cursor])) {
			cursor++
		}
		var delimiter strings.Builder
		var delimiterQuote byte
		quoted := false
		for cursor < len(line) {
			character = line[cursor]
			if delimiterQuote != 0 {
				if character == delimiterQuote {
					delimiterQuote = 0
				} else if character == '\\' && delimiterQuote == '"' && cursor+1 < len(line) {
					cursor++
					delimiter.WriteByte(line[cursor])
				} else {
					delimiter.WriteByte(character)
				}
				cursor++
				continue
			}
			if character == '\'' || character == '"' {
				quoted = true
				delimiterQuote = character
				cursor++
				continue
			}
			if character == '\\' && cursor+1 < len(line) {
				quoted = true
				cursor++
				delimiter.WriteByte(line[cursor])
				cursor++
				continue
			}
			if unicode.IsSpace(rune(character)) || strings.ContainsRune(";&|<>(){}", rune(character)) {
				break
			}
			delimiter.WriteByte(character)
			cursor++
		}
		if delimiterQuote != 0 || delimiter.Len() == 0 {
			return nil, quote, false
		}
		found = append(found, phaseHeredoc{delimiter: delimiter.String(), stripTabs: stripTabs, quoted: quoted})
		index = cursor - 1
	}
	return found, quote, true
}

func phaseInsideShellArithmetic(line string, index int) bool {
	prefix := line[:index]
	open := strings.LastIndex(prefix, "((")
	close := strings.LastIndex(prefix, "))")
	return open >= 0 && open > close
}

func phaseLineExecutesHeredocBody(line string) bool {
	words, valid := phaseTokenizeShell(line)
	if !valid {
		return true
	}
	segment := make([]string, 0, 8)
	for _, word := range words {
		if word.control {
			if phaseSimpleCommandReadsShellFromStdin(segment) {
				return true
			}
			segment = segment[:0]
		} else {
			segment = append(segment, word.value)
		}
	}
	return phaseSimpleCommandReadsShellFromStdin(segment)
}

func phaseSimpleCommandReadsShellFromStdin(words []string) bool {
	cleaned := make([]string, 0, len(words))
	for index := 0; index < len(words); index++ {
		if words[index] == phaseShellRedirect {
			index++
		} else {
			cleaned = append(cleaned, words[index])
		}
	}
	words = cleaned
	for len(words) > 0 && (phaseAssignment(words[0]) || phaseCommandPrefix(words[0])) {
		words = words[1:]
	}
	for len(words) > 0 {
		executable := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(words[0], `\`, "/"))), ".exe")
		if executable == "env" || executable == "sudo" || executable == "command" || executable == "exec" ||
			executable == "nice" || executable == "nohup" || executable == "time" || executable == "timeout" {
			words = phaseUnwrapCommand(executable, words[1:])
			continue
		}
		if executable == "source" || executable == "." {
			for _, argument := range words[1:] {
				if phaseShellStdinPath(argument) {
					return true
				}
			}
			return false
		}
		if !phaseShellInterpreter(executable) {
			return false
		}
		stdinMode := false
		for index := 1; index < len(words); index++ {
			argument := words[index]
			lower := strings.ToLower(argument)
			isCommand := executable == "cmd" && lower == "/c" ||
				(executable == "powershell" || executable == "pwsh") && lower == "-command" ||
				executable != "cmd" && executable != "powershell" && executable != "pwsh" &&
					strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") && strings.Contains(argument[1:], "c")
			if isCommand || (executable == "powershell" || executable == "pwsh") && (lower == "-encodedcommand" || lower == "-enc") {
				return index+1 < len(words) && phaseShellStdinPath(words[index+1])
			}
			if lower == "-file" {
				return index+1 < len(words) && phaseShellStdinPath(words[index+1])
			}
			if lower == "-s" || (executable != "powershell" && executable != "pwsh" &&
				strings.HasPrefix(lower, "-") && !strings.HasPrefix(lower, "--") && strings.Contains(lower[1:], "s")) {
				stdinMode = true
				continue
			}
			if lower == "--rcfile" || lower == "--init-file" || lower == "-o" || lower == "+o" ||
				(executable == "fish" && (argument == "-C" || lower == "--init-command")) {
				index++
				continue
			}
			if phaseShellStdinPath(argument) {
				return true
			}
			if argument == "--" || strings.HasPrefix(argument, "-") || stdinMode {
				continue
			}
			return false
		}
		return true
	}
	return false
}

func phaseShellStdinPath(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

func phaseShellSegmentHasCommand(words []string) bool {
	for index := 0; index < len(words); index++ {
		if words[index] == phaseShellRedirect {
			index++
			continue
		}
		if phaseAssignment(words[index]) || phaseCommandPrefix(words[index]) {
			continue
		}
		return true
	}
	return false
}

func phaseTokenizeShell(command string) ([]phaseShellWord, bool) {
	words := make([]phaseShellWord, 0, 16)
	var word strings.Builder
	var quote rune
	escaped, comment := false, false
	flush := func() {
		if word.Len() != 0 {
			words = append(words, phaseShellWord{value: word.String()})
			word.Reset()
		}
	}
	characters := []rune(command)
	for index, character := range characters {
		if comment {
			if character == '\n' {
				comment = false
				words = append(words, phaseShellWord{control: true})
			}
			continue
		}
		if escaped {
			word.WriteRune(character)
			escaped = false
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else if quote == '"' && character == '\\' {
				if index+1 < len(characters) && (characters[index+1] == '$' || characters[index+1] == '`' ||
					characters[index+1] == '"' || characters[index+1] == '\\' || characters[index+1] == '\n') {
					escaped = true
				} else {
					word.WriteRune(character)
				}
			} else {
				word.WriteRune(character)
			}
			continue
		}
		switch character {
		case '\\':
			escaped = true
		case '\'', '"':
			quote = character
		case '#':
			if word.Len() == 0 {
				comment = true
			} else {
				word.WriteRune(character)
			}
		case '>', '<':
			if word.Len() != 0 && !phaseDigits(word.String()) {
				flush()
			} else {
				word.Reset()
			}
			if len(words) == 0 || words[len(words)-1].value != phaseShellRedirect {
				words = append(words, phaseShellWord{value: phaseShellRedirect})
			}
		case ';', '&', '|', '\n', '(', ')', '{', '}':
			flush()
			words = append(words, phaseShellWord{control: true})
		default:
			if unicode.IsSpace(character) {
				flush()
			} else {
				word.WriteRune(character)
			}
		}
	}
	flush()
	return words, quote == 0 && !escaped
}

// phaseCommandWords drops redirections, leading assignments, and command
// prefixes, leaving the executable and its arguments.
func phaseCommandWords(words []string) []string {
	cleaned := make([]string, 0, len(words))
	for index := 0; index < len(words); index++ {
		if words[index] == phaseShellRedirect {
			index++
		} else {
			cleaned = append(cleaned, words[index])
		}
	}
	for len(cleaned) > 0 && (phaseAssignment(cleaned[0]) || phaseCommandPrefix(cleaned[0])) {
		cleaned = cleaned[1:]
	}
	return cleaned
}

func phaseExecutableName(word string) string {
	return strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(word, `\`, "/"))), ".exe")
}

func phaseWrapperExecutable(executable string) bool {
	return executable == "env" || executable == "sudo" || executable == "command" || executable == "exec" ||
		executable == "nice" || executable == "nohup" || executable == "time" || executable == "timeout"
}

// phaseInterpreterScript returns the script a shell interpreter or eval runs.
// ok is false when there is none or it is only known at run time (a
// variable, an encoded command, or a script file).
func phaseInterpreterScript(executable string, words []string) (string, bool) {
	arguments := words[1:]
	switch executable {
	case "eval":
		if len(arguments) == 0 {
			return "", false
		}
		return phaseLiteralScript(strings.Join(arguments, " "))
	case "powershell", "pwsh":
		return phasePowerShellScript(arguments)
	case "cmd":
		for index, argument := range arguments {
			if flag := strings.ToLower(argument); flag == "/c" || flag == "/k" {
				// cmd runs the rest of the line.
				return phaseLiteralScript(strings.Join(arguments[index+1:], " "))
			}
		}
		return "", false
	case "fish":
		// fish runs every -c / --command and -C / --init-command value as its
		// own script. Newlines keep a trailing # comment in one from hiding
		// the next.
		var scripts []string
		for index := 0; index < len(arguments); index++ {
			argument := arguments[index]
			if value, found := strings.CutPrefix(argument, "--command="); found {
				scripts = append(scripts, value)
				continue
			}
			if value, found := strings.CutPrefix(argument, "--init-command="); found {
				scripts = append(scripts, value)
				continue
			}
			if argument == "--command" || argument == "--init-command" {
				if index+1 < len(arguments) {
					index++
					scripts = append(scripts, arguments[index])
				}
				continue
			}
			if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") {
				continue
			}
			// Short options may be grouped (-ic) and the value may be
			// attached (-c'git push').
			if flag := strings.IndexAny(argument[1:], "cC"); flag >= 0 {
				if attached := argument[flag+2:]; attached != "" {
					scripts = append(scripts, attached)
				} else if index+1 < len(arguments) {
					index++
					scripts = append(scripts, arguments[index])
				}
			}
		}
		if len(scripts) == 0 {
			return "", false
		}
		return phaseLiteralScript(strings.Join(scripts, "\n"))
	}
	// POSIX shells: the first non-option word after -c is the script; later
	// words are positional parameters.
	for index, argument := range arguments {
		argument = strings.ToLower(argument)
		if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") || !strings.Contains(argument[1:], "c") {
			continue
		}
		script := index + 1
		if script < len(arguments) && arguments[script] == "--" {
			script++
		}
		if script >= len(arguments) {
			return "", false
		}
		return phaseLiteralScript(arguments[script])
	}
	return "", false
}

// phasePowerShellScript reads pwsh / powershell.exe arguments. -Command (and
// any prefix of it, such as -c) runs every remaining word; -CommandWithArgs
// runs only the next word and passes the rest as $args.
func phasePowerShellScript(arguments []string) (string, bool) {
	for index := 0; index < len(arguments); index++ {
		flag := strings.ToLower(arguments[index])
		if !strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "/") {
			continue
		}
		name := strings.TrimLeft(flag, "-/")
		switch {
		case name == "":
			continue
		case name == "cwa" || (len(name) > len("command") && strings.HasPrefix("commandwithargs", name)):
			if index+1 >= len(arguments) {
				return "", false
			}
			return phaseLiteralScript(arguments[index+1])
		case strings.HasPrefix("command", name):
			return phaseLiteralScript(strings.Join(arguments[index+1:], " "))
		case name == "e" || name == "ec" || (len(name) > 2 && strings.HasPrefix("encodedcommand", name)),
			name == "f" || strings.HasPrefix("file", name):
			// An encoded command or a script file cannot be inspected here.
			return "", false
		case name == "ep" || name == "ex" || strings.HasPrefix("executionpolicy", name) && len(name) > 2,
			name == "wd" || strings.HasPrefix("workingdirectory", name) && len(name) > 1,
			name == "w" || strings.HasPrefix("windowstyle", name) && len(name) > 1,
			strings.HasPrefix("configurationname", name) && len(name) > 6,
			strings.HasPrefix("settingsfile", name) && len(name) > 1,
			name == "of" || strings.HasPrefix("outputformat", name) && len(name) > 1,
			name == "if" || strings.HasPrefix("inputformat", name) && len(name) > 1:
			index++ // the flag's value
		}
	}
	return "", false
}

// phaseLiteralScript rejects scripts that only exist at run time.
func phaseLiteralScript(script string) (string, bool) {
	script = strings.TrimSpace(script)
	if script == "" || strings.HasPrefix(script, "$") || strings.HasPrefix(script, "%") {
		return "", false
	}
	return script, true
}

// phaseNestedShellScript returns the script a command hands to another shell,
// looking through wrappers such as env or sudo.
func phaseNestedShellScript(words []string) (string, bool) {
	words = phaseCommandWords(words)
	if len(words) == 0 {
		return "", false
	}
	executable := phaseExecutableName(words[0])
	switch {
	case phaseShellInterpreter(executable) || executable == "eval":
		return phaseInterpreterScript(executable, words)
	case phaseWrapperExecutable(executable):
		return phaseNestedShellScript(phaseUnwrapCommand(executable, words[1:]))
	}
	return "", false
}

func phaseSimpleCommandRequiresPhase(words []string) bool {
	words = phaseCommandWords(words)
	if len(words) == 0 {
		return false
	}
	executable := phaseExecutableName(words[0])
	if executable == "phase" || executable == "phase-dev" || executable == "phase-hook" {
		return false
	}
	if phaseShellInterpreter(executable) || executable == "eval" {
		script, ok := phaseInterpreterScript(executable, words)
		return ok && shellCommandRequiresPhase(script)
	}
	if phaseWrapperExecutable(executable) {
		return phaseSimpleCommandRequiresPhase(phaseUnwrapCommand(executable, words[1:]))
	}
	if phaseNetworkExecutable(executable) {
		for index, argument := range words[1:] {
			if phaseNetworkNonTargetValue(executable, words[1:], index) {
				continue
			}
			if phaseManagedTarget(argument) {
				return true
			}
		}
	}
	return false
}

func phaseNetworkNonTargetValue(executable string, arguments []string, index int) bool {
	if index <= 0 {
		return false
	}
	previousRaw := arguments[index-1]
	previous := strings.ToLower(previousRaw)
	switch executable {
	case "curl":
		if previousRaw == "-F" || previousRaw == "-H" {
			return true
		}
		switch previous {
		case "-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
			"--form", "--form-string", "--header", "-o", "--output", "-w", "--write-out":
			return true
		}
	case "wget":
		return previous == "-o" || previous == "--output-document" || previous == "--output-file"
	}
	return false
}

func phaseUnwrapCommand(wrapper string, words []string) []string {
	skippedTimeoutDuration := false
	for index := 0; index < len(words); index++ {
		word := words[index]
		if word == "--" {
			return words[index+1:]
		}
		if wrapper == "command" && (word == "-v" || word == "-V") {
			return nil
		}
		if phaseAssignment(word) {
			continue
		}
		if strings.HasPrefix(word, "-") {
			lower := strings.ToLower(word)
			if (wrapper == "sudo" && (word == "-C" || word == "-D" || word == "-g" || word == "-h" || word == "-p" ||
				word == "-R" || word == "-r" || word == "-T" || word == "-t" || word == "-U" || word == "-u" || lower == "--chdir" ||
				lower == "--chroot" || lower == "--close-from" || lower == "--command-timeout" || lower == "--group" ||
				lower == "--host" || lower == "--prompt" || lower == "--role" || lower == "--type" || lower == "--user")) ||
				(wrapper == "env" && (lower == "-u" || lower == "--unset" || lower == "-c" || lower == "--chdir" ||
					lower == "-s" || lower == "--split-string")) ||
				(wrapper == "nice" && (word == "-n" || word == "--adjustment")) ||
				(wrapper == "timeout" && (lower == "-k" || lower == "--kill-after" || lower == "-s" || lower == "--signal")) ||
				(wrapper == "time" && (lower == "-f" || lower == "--format" || lower == "-o" || lower == "--output")) ||
				(wrapper == "exec" && (lower == "-a" || lower == "--argv0")) {
				if !strings.Contains(word, "=") {
					index++
				}
			}
			continue
		}
		if wrapper == "timeout" && !skippedTimeoutDuration {
			skippedTimeoutDuration = true
			continue
		}
		return words[index:]
	}
	return nil
}

func phaseShellSubcommands(command string) ([]string, bool) {
	commands := make([]string, 0, 2)
	var quote byte
	for index := 0; index < len(command); index++ {
		character := command[index]
		if character == '\\' {
			index++
			continue
		}
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			}
			continue
		}
		if character == '\'' && quote == 0 {
			quote = '\''
			continue
		}
		if character == '"' {
			quote ^= '"'
			continue
		}
		if quote == 0 && character == '#' && (index == 0 || unicode.IsSpace(rune(command[index-1]))) {
			if newline := strings.IndexByte(command[index:], '\n'); newline >= 0 {
				index += newline
				continue
			}
			return commands, true
		}
		if character == '`' {
			end := strings.IndexByte(command[index+1:], '`')
			if end < 0 {
				return nil, false
			}
			end += index + 1
			commands = append(commands, command[index+1:end])
			index = end
			continue
		}
		if character != '$' || index+1 >= len(command) || command[index+1] != '(' {
			continue
		}
		end, valid := phaseSubcommandEnd(command, index+2)
		if !valid {
			return nil, false
		}
		if index+2 < len(command) && command[index+2] == '(' {
			inner, valid := phaseShellSubcommands(command[index+3 : end-1])
			if !valid {
				return nil, false
			}
			commands = append(commands, inner...)
		} else {
			commands = append(commands, command[index+2:end])
		}
		index = end
	}
	return commands, quote == 0
}

func phaseSubcommandEnd(command string, start int) (int, bool) {
	depth := 1
	var quote byte
	for index := start; index < len(command); index++ {
		character := command[index]
		if character == '\\' {
			index++
		} else if quote != 0 {
			if character == quote {
				quote = 0
			}
		} else if character == '\'' || character == '"' {
			quote = character
		} else if character == '(' {
			depth++
		} else if character == ')' {
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return len(command), false
}

func phaseManagedTarget(value string) bool {
	if strings.HasPrefix(value, "-") {
		option, target, present := strings.Cut(value, "=")
		if !present || !strings.EqualFold(option, "--url") {
			return false
		}
		value = target
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		parsed, _ = url.Parse("//" + strings.Trim(value, "[]'\".,"))
		host = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	return host == "phase.invalid"
}

func phaseNetworkExecutable(executable string) bool {
	return executable == "curl" || executable == "http" || executable == "httpie" || executable == "openssl" || executable == "wget"
}

func phaseShellInterpreter(executable string) bool {
	return executable == "bash" || executable == "cmd" || executable == "dash" || executable == "fish" ||
		executable == "ksh" || executable == "powershell" || executable == "pwsh" || executable == "sh" || executable == "zsh"
}

func phaseAssignment(value string) bool {
	name, _, present := strings.Cut(value, "=")
	if !present || name == "" {
		return false
	}
	for index, character := range name {
		if character != '_' && !unicode.IsLetter(character) && !(index > 0 && unicode.IsDigit(character)) {
			return false
		}
	}
	return true
}

func phaseCommandPrefix(value string) bool {
	switch strings.ToLower(value) {
	case "!", "do", "done", "elif", "else", "fi", "if", "then", "until", "while":
		return true
	}
	return false
}

func phaseDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}
