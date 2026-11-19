package censor

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Form identifiers, as they appear in Entries and in findings.
const (
	formRaw                = "raw"
	formNewlineLiteral     = "newline-literal"
	formNewlineLiteralJSON = "newline-literal-json"
	formBase64             = "base64"
	formBase64URL          = "base64url"
	formHex                = "hex"
	formURL                = "url"
	formJSON               = "json"
	formLine               = "line"
)

// formShape is what the scan needs to know about a form beyond its hashes. It is
// fixed by the form's identifier, so a client cannot choose it.
type formShape struct {
	class    *[256]bool
	slack    int
	wholeRun bool // a base64 or hex form: a match takes the whole run it sits in
}

var formShapes = map[string]formShape{
	formRaw:                {class: &classToken},
	formNewlineLiteral:     {class: &classToken},
	formNewlineLiteralJSON: {class: &classToken},
	formJSON:               {class: &classToken},
	formLine:               {class: &classToken},
	formBase64:             {class: &classB64, slack: 3, wholeRun: true},
	formBase64URL:          {class: &classB64URL, slack: 3, wholeRun: true},
	formHex:                {class: &classHex, wholeRun: true},
	formURL:                {class: &classURL},
}

// rawForm is a form while it is being indexed. Its bytes are dropped afterwards.
type rawForm struct {
	name  string
	bytes []byte
}

// encodedForms lists how a value commonly appears in a model request.
func encodedForms(value string) []rawForm {
	raw := []byte(value)
	forms := []rawForm{{name: formRaw, bytes: raw}}
	if strings.Contains(value, "\n") {
		// A PEM block written into an env file.
		literal := strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\n", `\n`)
		forms = append(forms,
			rawForm{name: formNewlineLiteral, bytes: []byte(literal)},
			rawForm{name: formNewlineLiteralJSON, bytes: []byte(jsonEscape(literal))},
		)
	}
	for _, variant := range []struct {
		name     string
		encoding *base64.Encoding
	}{
		{formBase64, base64.StdEncoding},
		{formBase64URL, base64.URLEncoding},
	} {
		// A value inside a larger blob, such as user:token in a Basic auth header,
		// sits at one of three alignments. Only the characters built entirely
		// from the value's own bits are predictable, so the edges are trimmed.
		for shift := 0; shift < 3; shift++ {
			padded := append(make([]byte, shift), raw...)
			encoded := variant.encoding.WithPadding(base64.NoPadding).EncodeToString(padded)
			head := []int{0, 2, 3}[shift]
			tail := len(padded) * 8 / 6
			if tail > head {
				forms = append(forms, rawForm{name: variant.name, bytes: []byte(encoded[head:tail])})
			}
		}
	}
	lower := hex.EncodeToString(raw)
	forms = append(forms,
		rawForm{name: formHex, bytes: []byte(lower)},
		rawForm{name: formHex, bytes: []byte(strings.ToUpper(lower))},
		rawForm{name: formURL, bytes: []byte(url.QueryEscape(value))},
		rawForm{name: formURL, bytes: []byte(url.PathEscape(value))},
		rawForm{name: formURL, bytes: []byte(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))},
		rawForm{name: formURL, bytes: []byte(lowerEscapes(url.QueryEscape(value)))},
		rawForm{name: formURL, bytes: []byte(lowerEscapes(url.PathEscape(value)))},
		rawForm{name: formURL, bytes: []byte(lowerEscapes(strings.ReplaceAll(url.QueryEscape(value), "+", "%20")))},
		rawForm{name: formJSON, bytes: []byte(jsonEscape(value))},
		rawForm{name: formJSON, bytes: []byte(jsonEscapeHTML(value))},
	)
	return forms
}

// lowerEscapes writes the two digits of every %XX in lower case, as some
// encoders do.
func lowerEscapes(escaped string) string {
	out := []byte(escaped)
	for i := 0; i+2 < len(out); i++ {
		if out[i] == '%' {
			out[i+1], out[i+2] = lowerTable[out[i+1]], lowerTable[out[i+2]]
		}
	}
	return string(out)
}

func jsonEscape(value string) string {
	var out strings.Builder
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return value
	}
	text := strings.TrimSuffix(out.String(), "\n")
	return text[1 : len(text)-1]
}

func jsonEscapeHTML(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	return string(encoded[1 : len(encoded)-1])
}

// structuralPrefix is a token's type prefix, such as pss_service:v2: or sk_live_.
var structuralPrefix = regexp.MustCompile(`^(?:[a-z]+[_:-]){1,4}(?:v\d+[_:-])?`)

// weakMask marks the bytes of a value that are structure rather than secret: a
// token's type prefix, PEM armour lines, and all of a URL but its password. It is
// nil when there is none.
func weakMask(value string) []bool {
	mask := make([]bool, len(value))
	marked := false
	mark := func(from, to int) {
		for i := from; i < to; i++ {
			mask[i] = true
		}
		marked = marked || to > from
	}
	if m := structuralPrefix.FindStringIndex(value); m != nil && m[1] <= 16 {
		mark(0, m[1])
	}
	// A JWT's header segment is shared by every token signed the same way. Its
	// claims segment starts the same way across tokens too, so only the
	// signature counts as the secret.
	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
		mark(0, strings.LastIndex(value, ".")+1)
	}
	offset := 0
	for _, line := range strings.SplitAfter(value, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-----") {
			mark(offset, offset+len(line))
		}
		offset += len(line)
	}
	if from, to, ok := credentialSpan(value); ok {
		mark(0, from)
		mark(to, len(value))
	}
	if !marked {
		return nil
	}
	return mask
}

// decoyOf changes every letter and digit that isn't structure, and the last
// byte of every character past ASCII. Punctuation stays and what is changed is
// escaped as it was, so each form of the decoy is as long as the value's and
// their chunks line up: a password with %40 or '!' in it would otherwise leave
// the URL-encoded forms without a decoy, and their host chunks counting.
func decoyOf(value string, mask []bool) string {
	decoy := []byte(value)
	for i, b := range decoy {
		switch {
		case mask[i]:
		case b == 'x':
			decoy[i] = 'y'
		case (b >= '0' && b <= '9') || (lowerTable[b] >= 'a' && lowerTable[b] <= 'z'):
			decoy[i] = 'x'
		case b >= 0x80 && b < 0xc0 && (i+1 == len(decoy) || decoy[i+1] < 0x80 || decoy[i+1] >= 0xc0):
			decoy[i] = b ^ 1
		}
	}
	return string(decoy)
}

// urlPassword is the password of a URL such as postgres://user:password@host/db.
func urlPassword(value string) string {
	if !strings.Contains(value, "://") || strings.ContainsAny(value, " \n") {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return ""
	}
	password, _ := parsed.User.Password()
	return password
}

// urlCredential is what in a URL's userinfo is a secret: its password, or with
// no password a user long enough to be a token, as in https://<token>@host.
func urlCredential(value string) string {
	if password := urlPassword(value); password != "" {
		return password
	}
	if !strings.Contains(value, "://") || strings.ContainsAny(value, " \n") {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil || len(parsed.User.Username()) < minValueLength {
		return ""
	}
	return parsed.User.Username()
}

// credentialSpan is where a URL's credential sits in the URL as it is written,
// which is not the credential itself when it holds an escape such as %40.
func credentialSpan(value string) (from, to int, ok bool) {
	if urlCredential(value) == "" {
		return 0, 0, false
	}
	// The authority ends at the first '/', '?' or '#', its user and password
	// at the last '@', and the user at the first ':'.
	host := strings.Index(value, "://") + len("://")
	end := len(value)
	if i := strings.IndexAny(value[host:], "/?#"); i >= 0 {
		end = host + i
	}
	at := strings.LastIndexByte(value[host:end], '@')
	if at < 0 {
		return 0, 0, false
	}
	colon := strings.IndexByte(value[host:host+at], ':')
	switch {
	case urlPassword(value) == "" && colon < 0:
		return host, host + at, true
	case urlPassword(value) == "":
		return host, host + colon, true
	case colon < 0:
		return 0, 0, false
	}
	return host + colon + 1, host + at, true
}

// entropy is the Shannon entropy of the bytes, in bits per byte.
func entropy(value string) float64 {
	if value == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	total := float64(len(value))
	var bitsPerByte float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		bitsPerByte -= p * math.Log2(p)
	}
	return bitsPerByte
}

// secretLine reports whether a line of a multiline value is a secret in itself:
// one run of base64, base64url or hex characters, padded or not, that mixes
// digits with letters or the two cases of letters, as a line of a PEM body or of
// an encoded key does. Words, names and key: value lines are none.
func secretLine(line string) bool {
	body := strings.TrimRight(line, "=")
	if len(line)-len(body) > 2 {
		return false
	}
	standard, urlSafe := true, true
	var digit, lower, upper bool
	for i := 0; i < len(body); i++ {
		switch b := body[i]; {
		case b >= '0' && b <= '9':
			digit = true
		case b >= 'a' && b <= 'z':
			lower = true
		case b >= 'A' && b <= 'Z':
			upper = true
		case b == '+' || b == '/':
			urlSafe = false
		case b == '-' || b == '_':
			standard = false
		default:
			return false
		}
	}
	return (standard || urlSafe) && ((digit && (lower || upper)) || (lower && upper))
}

type leaf struct{ path, value string }

// jsonLeaves lists the string leaves of a JSON object or array, in a stable order.
func jsonLeaves(value string) []leaf {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}
	var root any
	if json.Unmarshal([]byte(trimmed), &root) != nil {
		return nil
	}
	var leaves []leaf
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch typed := node.(type) {
		case string:
			leaves = append(leaves, leaf{path: path, value: strings.TrimSpace(typed)})
		case []any:
			for i, item := range typed {
				walk(item, path+"["+strconv.Itoa(i)+"]")
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				next := key
				if path != "" {
					next = path + "." + key
				}
				walk(typed[key], next)
			}
		}
	}
	walk(root, "")
	return leaves
}

// keyNumbers counts what in a JSON document looks like key material written as
// numbers: an array of 16 or more integers, as the bytes of a keypair are, and
// an integer of 12 or more digits.
func keyNumbers(value string) int {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var root any
	if decoder.Decode(&root) != nil {
		return 0
	}
	digits := func(node any) int {
		number, ok := node.(json.Number)
		text := strings.TrimPrefix(string(number), "-")
		if !ok || strings.ContainsAny(text, ".eE") {
			return 0
		}
		return len(text)
	}
	count := 0
	var walk func(node any)
	walk = func(node any) {
		switch typed := node.(type) {
		case json.Number:
			if digits(typed) >= 12 {
				count++
			}
		case []any:
			integers := len(typed) >= 16
			for _, item := range typed {
				integers = integers && digits(item) > 0
			}
			if integers {
				count++
				return
			}
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(root)
	return count
}

// looksPublic keeps a key file's URLs and identity out of the index: redacting them
// would hide ordinary text without protecting anything. A URL with a password in
// it, or a token for its user, is a credential.
func looksPublic(value string) bool {
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return !strings.ContainsAny(value, " \n") && urlCredential(value) == ""
	}
	if at := strings.IndexByte(value, '@'); at > 0 && !strings.ContainsAny(value, " \n:/") && strings.Contains(value[at:], ".") {
		return true
	}
	return false
}

var (
	classToken  [256]bool
	classB64    [256]bool
	classB64URL [256]bool
	classHex    [256]bool
	classURL    [256]bool
	classRun    [256]bool // any base64 alphabet: what the decode pass looks for
)

func init() {
	for b := 0x21; b < 0x7f; b++ {
		classToken[b] = !strings.ContainsRune("\"'`<>\\", rune(b))
	}
	for b := 0x80; b < 0x100; b++ {
		classToken[b] = true
	}
	alnum := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for _, set := range []struct {
		class *[256]bool
		chars string
	}{
		{&classB64, alnum + "+/="},
		{&classB64URL, alnum + "-_="},
		{&classHex, "0123456789abcdefABCDEF"},
		{&classURL, alnum + "-._~%+"},
	} {
		for i := 0; i < len(set.chars); i++ {
			set.class[set.chars[i]] = true
		}
	}
	for b := range classB64 {
		classRun[b] = classB64[b] || classB64URL[b]
	}
}
