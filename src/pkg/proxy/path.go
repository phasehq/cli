package proxy

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

func canonicalHTTPPath(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		// RequestURI rejects a plain path containing some valid escaped bytes;
		// fall back to treating the input as a path only.
		parsed = &url.URL{Path: value}
	}
	decoded, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || strings.ContainsRune(decoded, '\x00') {
		return "", errors.New("invalid HTTP path")
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(decoded, "/"))
	if cleaned == "." {
		cleaned = "/"
	}
	return cleaned, nil
}

func globMatch(pattern, value string) bool {
	var expression strings.Builder
	expression.WriteString("(?s)^")
	characters := []rune(pattern)
	for index := 0; index < len(characters); {
		character := characters[index]
		switch character {
		case '*':
			expression.WriteString(".*")
			for index+1 < len(characters) && characters[index+1] == '*' {
				index++
			}
		case '?':
			expression.WriteByte('.')
		case '[':
			translated, next, ok := translateGlobClass(characters, index+1)
			if ok {
				expression.WriteString(translated)
				index = next
				continue
			}
			expression.WriteString(`\[`)
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
		index++
	}
	expression.WriteByte('$')
	matched, err := regexp.MatchString(expression.String(), value)
	return err == nil && matched
}

// translateGlobClass mirrors Python fnmatchcase's bracket-class translation.
// start points just after '['; next is the rune after the closing ']'.
func translateGlobClass(pattern []rune, start int) (translated string, next int, ok bool) {
	end := start
	if end < len(pattern) && pattern[end] == '!' {
		end++
	}
	if end < len(pattern) && pattern[end] == ']' {
		end++
	}
	for end < len(pattern) && pattern[end] != ']' {
		end++
	}
	if end >= len(pattern) {
		return "", start, false
	}
	stuff := translateGlobClassStuff(pattern, start, end)
	switch stuff {
	case "":
		// An empty or wholly invalid range can never match. This fragment is
		// intentionally impossible but remains valid in Go's RE2 syntax.
		return `(?:a\A)`, end + 1, true
	case "!":
		return ".", end + 1, true
	}
	if stuff[0] == '!' {
		stuff = "^" + stuff[1:]
	} else if stuff[0] == '^' || stuff[0] == '[' {
		stuff = `\` + stuff
	}
	return "[" + stuff + "]", end + 1, true
}

func translateGlobClassStuff(pattern []rune, start, end int) string {
	containsHyphen := false
	for _, character := range pattern[start:end] {
		if character == '-' {
			containsHyphen = true
			break
		}
	}
	if !containsHyphen {
		return escapeGlobClassChunk(pattern[start:end], false)
	}

	chunks := make([][]rune, 0)
	cursor := start
	search := start + 1
	if start < end && pattern[start] == '!' {
		search = start + 2
	}
	for {
		dash := -1
		for index := search; index < end; index++ {
			if pattern[index] == '-' {
				dash = index
				break
			}
		}
		if dash < 0 {
			break
		}
		chunks = append(chunks, append([]rune(nil), pattern[cursor:dash]...))
		cursor = dash + 1
		search = dash + 3
	}
	if cursor < end {
		chunks = append(chunks, append([]rune(nil), pattern[cursor:end]...))
	} else if len(chunks) > 0 {
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], '-')
	}
	// CPython removes descending ranges because they are invalid in a regular
	// expression. Preserve any surrounding literals on either side.
	for index := len(chunks) - 1; index > 0; index-- {
		left, right := chunks[index-1], chunks[index]
		if len(left) > 0 && len(right) > 0 && left[len(left)-1] > right[0] {
			combined := append(append([]rune(nil), left[:len(left)-1]...), right[1:]...)
			chunks[index-1] = combined
			chunks = append(chunks[:index], chunks[index+1:]...)
		}
	}
	parts := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		parts = append(parts, escapeGlobClassChunk(chunk, true))
	}
	return strings.Join(parts, "-")
}

func escapeGlobClassChunk(chunk []rune, escapeHyphen bool) string {
	var escaped strings.Builder
	for _, character := range chunk {
		if character == '\\' || (escapeHyphen && character == '-') {
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}
