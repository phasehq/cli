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
	rooted := "/" + strings.TrimPrefix(decoded, "/")
	cleaned := path.Clean(rooted)
	// S3 keeps dot segments, repeated slashes and a trailing slash in object
	// keys, so a rule matches the path as sent and never one cleaning changes.
	if rooted != cleaned && (cleaned == "/" || rooted != cleaned+"/") {
		return "", errors.New("non-canonical HTTP path")
	}
	return rooted, nil
}

func globMatch(pattern, value string) bool {
	return globMatchWith(pattern, value, false)
}

// looseGlobMatch is globMatch for the comparisons that must not be dodged by
// respelling a path: it also matches when the pattern covers the path with
// letter case, one trailing slash and ";params" on any segment left out, which
// is how many servers route a request. Only what stops or reclassifies a call
// is compared this way (see ruleMatches in policy.go).
func looseGlobMatch(pattern, value string) bool {
	if globMatch(pattern, value) {
		return true
	}
	if len(pattern) > 1 {
		pattern = strings.TrimSuffix(pattern, "/")
	}
	return globMatchWith(pattern, loosePath(value), true)
}

// loosePath drops ";params" from every segment, then one trailing slash.
// Tomcat, Jetty and Spring route /a;x/b as /a/b.
func loosePath(value string) string {
	value = trimPathParams(value)
	if len(value) > 1 && strings.HasSuffix(value, "/") {
		value = value[:len(value)-1]
	}
	return value
}

func trimPathParams(value string) string {
	if !strings.Contains(value, ";") {
		return value
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		if parameters := strings.IndexByte(segment, ';'); parameters >= 0 {
			segments[index] = segment[:parameters]
		}
	}
	return strings.Join(segments, "/")
}

// loosePathMatch compares a path.Match pattern with a request path the way
// looseGlobMatch does, after cleaning repeated slashes and dot segments. It is
// for the fixed path tables that name one operation of a service.
func loosePathMatch(pattern, requestPath string) bool {
	cleaned := strings.ToLower(loosePath(path.Clean("/" + requestPath)))
	matched, err := path.Match(strings.ToLower(pattern), cleaned)
	return err == nil && matched
}

// guardPathMatch is loosePathMatch for a request, also tried with each path
// segment decoded on its own: GitLab and others take "group%2Fproject" as one
// segment, and an encoded slash must not carry a call past a rule.
func guardPathMatch(pattern string, requestURL *url.URL) bool {
	if loosePathMatch(pattern, requestURL.Path) {
		return true
	}
	segments := strings.Split(requestURL.EscapedPath(), "/")
	for index, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return false
		}
		segments[index] = strings.ReplaceAll(decoded, "/", "%2F")
	}
	return loosePathMatch(pattern, strings.Join(segments, "/"))
}

func globMatchWith(pattern, value string, foldCase bool) bool {
	var expression strings.Builder
	if foldCase {
		expression.WriteString("(?is)^")
	} else {
		expression.WriteString("(?s)^")
	}
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
