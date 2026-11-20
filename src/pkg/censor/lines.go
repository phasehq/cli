package censor

import (
	"strconv"
	"strings"
)

// Text of several lines that is mostly names and values, as a kubeconfig, an
// env file or an INI file is, is indexed the way a JSON document is: value by
// value. Its names, separators, comments and headers are in every file of its
// kind, and indexing them with the rest had lines such as apiVersion: v1
// replaced wherever they were written.

// What a line of such text is.
const (
	lineSyntax = iota // a comment, a header, a document marker, armour, or brackets alone
	lineNamed         // name: value or name=value; the value may be empty
	lineRun           // one run of base64 or hex characters, as a line of key data is
	lineOther         // anything else: a value that has no name
)

// maxLineName is the longest a name may be. One of 20 bytes or more that holds
// a digit and a letter is taken for a token instead, and its line for a value.
const (
	maxLineName   = 128
	tokenLineName = 20
)

type textLine struct {
	kind  int
	value string
}

// structuredLines reads a value as lines of names and values. It reports false
// unless the value has two or more lines that are not blank, does not begin
// with an armour line as a PEM block does, and at least half of those lines
// are a name and a value.
func structuredLines(value string) ([]textLine, bool) {
	if !strings.Contains(value, "\n") {
		return nil, false
	}
	var lines []textLine
	named := 0
	for _, raw := range strings.Split(value, "\n") {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		if len(lines) == 0 && strings.HasPrefix(text, "-----") {
			return nil, false
		}
		line := readLine(text)
		if line.kind == lineNamed {
			named++
		}
		lines = append(lines, line)
	}
	if len(lines) < 2 || 2*named < len(lines) {
		return nil, false
	}
	return lines, true
}

// readLine says what one line is, and what value it holds. text is trimmed and
// not empty.
func readLine(text string) textLine {
	switch {
	case text[0] == '#', text[0] == ';', strings.HasPrefix(text, "//"),
		text == "---", strings.HasPrefix(text, "--- "), text == "...", strings.HasPrefix(text, "-----"),
		text[0] == '[' && text[len(text)-1] == ']':
		return textLine{kind: lineSyntax}
	}
	// An item of a YAML sequence is read as the line after its marker.
	for strings.HasPrefix(text, "- ") {
		text = strings.TrimSpace(text[2:])
	}
	if text == "" || text == "-" {
		return textLine{kind: lineSyntax}
	}
	bare := plainValue(text)
	// NAME= is an assignment of nothing. Padded base64 is a multiple of four long.
	if secretLine(bare) && (!strings.HasSuffix(bare, "=") || len(bare)%4 == 0) {
		return textLine{kind: lineRun, value: bare}
	}
	if value, ok := valueAfterName(text); ok {
		return textLine{kind: lineNamed, value: value}
	}
	if !holdsAlphanumeric([]byte(bare)) {
		return textLine{kind: lineSyntax}
	}
	return textLine{kind: lineOther, value: bare}
}

// valueAfterName splits a line into a name and the value written after it:
// name: value as YAML and INI have it, name=value as an env file, a properties
// file or a command line flag does, with the name in quotes or after export.
func valueAfterName(text string) (string, bool) {
	text = strings.TrimPrefix(text, "export ")
	end := 0
	if text[0] == '"' || text[0] == '\'' {
		closing := strings.IndexByte(text[1:], text[0])
		if closing < 0 {
			return "", false
		}
		end = closing + 2
	} else {
		for end < len(text) && isIdentByte(text[end]) {
			end++
		}
		// A token where a name would be, as in a map keyed by tokens.
		if end >= tokenLineName && plausibleSecret([]byte(text[:end])) {
			return "", false
		}
	}
	if end == 0 || end > maxLineName {
		return "", false
	}
	rest := strings.TrimLeft(text[end:], " \t")
	switch {
	case strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "=="):
		return plainValue(rest[1:]), true
	case rest == ":" || strings.HasPrefix(rest, ": ") || strings.HasPrefix(rest, ":\t"):
		return plainValue(rest[1:]), true
	}
	return "", false
}

var doubleQuoted = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\"`, `"`, `\\`, `\`)

// plainValue is a value as the text means it: without the quotes around it and
// the comma or comment after them, and with the \n, \r, \" and \\ of a value
// in double quotes read as what they stand for.
func plainValue(text string) string {
	text = strings.TrimSpace(text)
	if len(text) < 2 || (text[0] != '"' && text[0] != '\'') {
		return text
	}
	end := 1
	for end < len(text) && text[end] != text[0] {
		if text[0] == '"' && text[end] == '\\' {
			end++
		}
		end++
	}
	if end >= len(text) {
		return text
	}
	if after := strings.TrimSpace(text[end+1:]); after != "" && after != "," && after[0] != '#' {
		return text
	}
	if text[0] == '"' {
		return doubleQuoted.Replace(text[1:end])
	}
	return text[1:end]
}

// addStructured indexes text that is names and values by its values, and
// reports whether the value was such text. A value after a name, and a line
// that is neither a name and a value nor syntax, is a leaf as a string of a
// JSON document is, held to the floor a value registered alone has; a line of
// key data keeps its line form. Nothing else of the text is indexed.
func (b *entriesBuilder) addStructured(value string) bool {
	lines, ok := structuredLines(value)
	if !ok {
		return false
	}
	leaves := 0
	seen := map[string]bool{}
	for _, line := range lines {
		switch line.kind {
		case lineNamed, lineOther:
			if line.value == "" {
				continue
			}
			b.addLeaf(partLeafPrefix+strconv.Itoa(leaves), line.value, minValueLength)
			leaves++
		case lineRun:
			if len(line.value) < minValueLength || entropy(line.value) < minValueEntropy || seen[line.value] {
				continue
			}
			seen[line.value] = true
			b.addForm("", line.value, rawForm{name: formLine, bytes: []byte(line.value)}, nil)
		}
	}
	// More parts than one entry holds: as plain text the value has few.
	if _, err := b.finish(); err != nil {
		b.entries.Forms, b.entries.Unprotected, b.chunks = nil, nil, 0
		return false
	}
	return true
}

// addLeaf indexes one value of a document on its own, unless it is public or
// under the floor: those are listed as unprotected.
func (b *entriesBuilder) addLeaf(part, value string, floor int) {
	if looksPublic(value) {
		b.skip(part, ReasonPublicLeaf)
		return
	}
	if len(value) < floor {
		b.skip(part, ReasonShortLeaf)
		return
	}
	b.addValue(part, value)
	// A URL's password, or the token that is its user, is also protected on
	// its own.
	if credential := urlCredential(value); credential != "" {
		b.addValue(part, credential)
	}
}
