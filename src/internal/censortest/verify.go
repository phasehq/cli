// Package censortest helps test leak protection: a fake-secret repository to
// scan, and a verifier that checks what a scan left behind. Both hold plaintext
// values, which is the opposite of what pkg/censor is for, so only tests may
// import this package.
//
// The verifier shares no code with pkg/censor. It finds values by plain
// substring search over their whole encoded forms and over fixed-length
// fragments, and names the form itself.
package censortest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Entry is one value the verifier looks for. Expect is "hit" or empty (a scan is
// meant to remove it), "rule" (only a pattern rule can remove it), "miss" (a scan
// is not meant to catch it) or "too_short" (it cannot be protected).
type Entry struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Expect string `json:"expect,omitempty"`
	Where  string `json:"where,omitempty"`
}

// Miss is a value still present in what was checked. It never holds the value.
type Miss struct {
	ID       string `json:"id"`
	Form     string `json:"form"`
	Part     string `json:"part,omitempty"`
	Expected bool   `json:"expected,omitempty"`
}

const (
	rawFragment    = 12 // shortest raw fragment that counts as a leak
	b64Fragment    = 16 // shortest piece of an aligned base64 form that counts
	hexFragment    = 24 // shortest hex fragment that counts
	fragmentMinLen = 16 // shortest value whose fragments are looked for
)

type unit struct {
	id, part, value string
	expected        bool
	forms           [][]byte
}

// Verifier is safe for concurrent use once built.
type Verifier struct {
	units     []unit
	fragments map[int]map[string][]int // fragment length -> fragment -> unit indexes
}

// NewVerifier builds a verifier. A JSON value is checked leaf by leaf, a PEM
// block line by line, a URL by its password and a JWT by its signature, because
// their keys, armour, hosts and headers would otherwise show up as fragments of
// every value of that kind.
func NewVerifier(entries []Entry) *Verifier {
	v := &Verifier{fragments: map[int]map[string][]int{}}
	seen := map[string]bool{}
	add := func(entry Entry, part, value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[entry.ID+"\x00"+part] {
			return
		}
		seen[entry.ID+"\x00"+part] = true
		expected := entry.Expect == "miss" || entry.Expect == "too_short"
		index := len(v.units)
		u := unit{id: entry.ID, part: part, value: value, expected: expected}
		whole, pieces := encodedForms(value)
		u.forms = whole
		v.units = append(v.units, u)
		if len(value) < fragmentMinLen {
			return
		}
		for _, piece := range pieces {
			for offset := 0; offset+piece.length <= len(piece.bytes); offset++ {
				byLength := v.fragments[piece.length]
				if byLength == nil {
					byLength = map[string][]int{}
					v.fragments[piece.length] = byLength
				}
				fragment := string(piece.bytes[offset : offset+piece.length])
				if list := byLength[fragment]; len(list) == 0 || list[len(list)-1] != index {
					byLength[fragment] = append(list, index)
				}
			}
		}
	}
	var addValue func(entry Entry, part, value string)
	addValue = func(entry Entry, part, value string) {
		value = strings.TrimSpace(value)
		if leaves := stringLeaves(value); leaves != nil {
			for path, leaf := range leaves {
				if len(leaf) >= 20 && !public(leaf) {
					addValue(entry, joinPart(part, "leaf:"+path), leaf)
				}
			}
			return
		}
		// A URL's scheme, user and host are not secret: only its password is checked.
		if parsed, err := url.Parse(value); err == nil && strings.Contains(value, "://") && parsed.User != nil {
			if password, ok := parsed.User.Password(); ok && len(password) >= 6 {
				add(entry, joinPart(part, "url-password"), password)
				return
			}
		}
		if strings.Contains(value, "-----BEGIN") {
			for i, line := range strings.Split(value, "\n") {
				line = strings.TrimSpace(line)
				if len(line) >= 16 && !strings.HasPrefix(line, "-----") {
					addValue(entry, joinPart(part, "pem-line:"+strconv.Itoa(i)), line)
				}
			}
			return
		}
		// A JWT's header is the same for every token signed the same way, and its
		// claims start alike too, so only the signature says this token leaked.
		if segments := strings.Split(value, "."); len(segments) == 3 && strings.HasPrefix(value, "eyJ") {
			add(entry, joinPart(part, "jwt-signature"), segments[2])
			return
		}
		add(entry, part, value)
	}
	for _, entry := range entries {
		addValue(entry, "", entry.Value)
	}
	return v
}

func joinPart(parent, part string) string {
	if parent == "" {
		return part
	}
	return parent + "/" + part
}

// Check returns every value present in payload, whole or as a fragment, in any
// form. JSON is also checked string by string after decoding, including JSON
// held inside a string.
func (v *Verifier) Check(payload []byte) []Miss {
	if len(v.units) == 0 {
		return nil
	}
	buffers := [][]byte{payload}
	var root any
	if json.Unmarshal(payload, &root) == nil {
		collectStrings(root, &buffers, 0)
	}
	found := map[Miss]bool{}
	for _, buffer := range buffers {
		for _, index := range v.scan(buffer) {
			u := v.units[index]
			found[Miss{ID: u.id, Part: u.part, Form: formOf(u.value, buffer), Expected: u.expected}] = true
		}
	}
	misses := make([]Miss, 0, len(found))
	for miss := range found {
		misses = append(misses, miss)
	}
	sort.Slice(misses, func(i, j int) bool {
		if misses[i].ID != misses[j].ID {
			return misses[i].ID < misses[j].ID
		}
		if misses[i].Part != misses[j].Part {
			return misses[i].Part < misses[j].Part
		}
		return misses[i].Form < misses[j].Form
	})
	return misses
}

func (v *Verifier) scan(buffer []byte) []int {
	hit := map[int]bool{}
	for i, u := range v.units {
		for _, form := range u.forms {
			if bytes.Contains(buffer, form) {
				hit[i] = true
				break
			}
		}
	}
	for length, byFragment := range v.fragments {
		for offset := 0; offset+length <= len(buffer); offset++ {
			for _, index := range byFragment[string(buffer[offset:offset+length])] {
				hit[index] = true
			}
		}
	}
	indexes := make([]int, 0, len(hit))
	for index := range hit {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	return indexes
}

func collectStrings(node any, buffers *[][]byte, depth int) {
	switch typed := node.(type) {
	case string:
		*buffers = append(*buffers, []byte(typed))
		trimmed := strings.TrimSpace(typed)
		if depth < 4 && len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
			var inner any
			if json.Unmarshal([]byte(trimmed), &inner) == nil {
				collectStrings(inner, buffers, depth+1)
			}
		}
	case []any:
		for _, item := range typed {
			collectStrings(item, buffers, depth)
		}
	case map[string]any:
		for _, item := range typed {
			collectStrings(item, buffers, depth)
		}
	}
}

// formOf names how the value appears in buffer. A value found that isn't present
// whole in any of these forms is a fragment, or an encoding inside a larger blob.
func formOf(value string, buffer []byte) string {
	raw := []byte(value)
	escaped, _ := json.Marshal(value)
	candidates := []struct {
		name    string
		encoded string
	}{
		{"raw", value},
		{"newline-literal", strings.ReplaceAll(value, "\n", `\n`)},
		{"json", string(escaped[1 : len(escaped)-1])},
		{"base64", strings.TrimRight(base64.StdEncoding.EncodeToString(raw), "=")},
		{"base64url", strings.TrimRight(base64.URLEncoding.EncodeToString(raw), "=")},
		{"hex", hex.EncodeToString(raw)},
		{"hex", strings.ToUpper(hex.EncodeToString(raw))},
		{"url", url.QueryEscape(value)},
		{"url", url.PathEscape(value)},
	}
	for _, candidate := range candidates {
		if bytes.Contains(buffer, []byte(candidate.encoded)) {
			return candidate.name
		}
	}
	return "fragment-or-embedded"
}

func stringLeaves(value string) map[string]string {
	if value == "" || (value[0] != '{' && value[0] != '[') {
		return nil
	}
	var root any
	if json.Unmarshal([]byte(value), &root) != nil {
		return nil
	}
	leaves := map[string]string{}
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch typed := node.(type) {
		case string:
			leaves[path] = typed
		case []any:
			for i, item := range typed {
				walk(item, path+"["+strconv.Itoa(i)+"]")
			}
		case map[string]any:
			for key, item := range typed {
				next := key
				if path != "" {
					next = path + "." + key
				}
				walk(item, next)
			}
		}
	}
	walk(root, "")
	return leaves
}

func public(value string) bool {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return true
	}
	at := strings.IndexByte(value, '@')
	return at > 0 && !strings.ContainsAny(value, " \n:/") && strings.Contains(value[at:], ".")
}
