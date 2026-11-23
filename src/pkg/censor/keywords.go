package censor

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"sort"
	"strings"
)

// keywordSet finds secret-sounding words case-insensitively in one pass. A table of
// the lowercase byte pairs keywords start with filters every offset, so the cost is
// a lookup per byte plus a comparison only where a keyword could begin.
type keywordSet struct {
	words  [][]byte
	starts [1 << 16]bool
	byPair map[uint16][]int
}

type keywordHit struct{ start, end int }

var lowerTable [256]byte

func init() {
	for i := range lowerTable {
		lowerTable[i] = byte(i)
		if i >= 'A' && i <= 'Z' {
			lowerTable[i] = byte(i) + 32
		}
	}
}

func newKeywordSet(words []string) *keywordSet {
	k := &keywordSet{byPair: map[uint16][]int{}}
	for _, word := range words {
		word = strings.ToLower(strings.TrimSpace(word))
		if len(word) < 2 {
			continue
		}
		pair := uint16(word[0])<<8 | uint16(word[1])
		k.starts[pair] = true
		k.byPair[pair] = append(k.byPair[pair], len(k.words))
		k.words = append(k.words, []byte(word))
	}
	return k
}

func (k *keywordSet) empty() bool { return k == nil || len(k.words) == 0 }

// find returns every keyword occurrence, ordered by where it ends.
func (k *keywordSet) find(data []byte) []keywordHit {
	if k.empty() || len(data) < 2 {
		return nil
	}
	var hits []keywordHit
	for i := 0; i+1 < len(data); i++ {
		pair := uint16(lowerTable[data[i]])<<8 | uint16(lowerTable[data[i+1]])
		if !k.starts[pair] {
			continue
		}
		for _, index := range k.byPair[pair] {
			word := k.words[index]
			if i+len(word) <= len(data) && equalLower(data[i:i+len(word)], word) {
				hits = append(hits, keywordHit{start: i, end: i + len(word)})
			}
		}
	}
	sort.Slice(hits, func(a, b int) bool { return hits[a].end < hits[b].end })
	return hits
}

func (k *keywordSet) containsFold(data []byte) bool {
	return len(data) > 0 && len(k.find(data)) > 0
}

func equalLower(data, word []byte) bool {
	for i, b := range word {
		if lowerTable[data[i]] != b {
			return false
		}
	}
	return true
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '-' || b == '.' || (b >= '0' && b <= '9') || lowerTable[b] >= 'a' && lowerTable[b] <= 'z'
}

func isSeparator(b byte) bool {
	switch b {
	case ' ', '\t', '"', '\'', ':', '=', '>':
		return true
	}
	return false
}

func isValueByte(b byte) bool {
	if b <= ' ' || b == 0x7f {
		return false
	}
	switch b {
	case '"', '\'', '`', ',', ';', '(', ')', '<', '>', '{', '}', '[', ']', '\\':
		return false
	}
	return true
}

// valueAfterKeyword finds the value assigned right after a keyword: the rest of the
// name (STRIPE_SECRET_KEY, client_secret), then a separator (=, :, a quote, a
// space), then one token, as in KEY=value, "key": "value", --token value,
// Password=value; or Authorization: Bearer value.
func valueAfterKeyword(data []byte, end, window int) (int, int, bool) {
	i := end
	for i < len(data) && i-end < 48 && isIdentByte(data[i]) {
		i++
	}
	separators := i
	for i < len(data) && i-end <= window && isSeparator(data[i]) {
		i++
	}
	if i == separators || i >= len(data) {
		return 0, 0, false
	}
	for _, scheme := range []string{"bearer ", "basic ", "token "} {
		if i+len(scheme) < len(data) && equalLower(data[i:i+len(scheme)], []byte(scheme)) {
			i += len(scheme)
			break
		}
	}
	start := i
	// '&' ends a value too: in a query string or a form body what follows is the
	// next field (refresh_token=X&client_id=Y), not more of the value.
	for i < len(data) && i-start < 512 && isValueByte(data[i]) && data[i] != '&' {
		i++
	}
	return start, i, i > start
}

// nameEnd is where the name a keyword sits in ends: the keyword's own end, and
// then as far as the name runs on (STRIPE_SECRET_KEY, secretName).
func nameEnd(data []byte, end int) int {
	i := end
	for i < len(data) && i-end < 48 && isIdentByte(data[i]) {
		i++
	}
	return i
}

// What a name says of its value when it runs on past the keyword. secretName
// holds the name of a secret, token_file a path, tokenizer_name a model and
// authDomain a host: none is the secret, and each is random enough to be taken
// for one. The word right after the keyword decides, whichever way the name is
// written (secretName, secret_name, SECRET-NAME, tokenizer), and so does the
// word the name ends on when it is one that names a label rather than a place
// (AUTH0_CLIENT_ID, password_policy_name): a name's last word is what the value
// is. A place can still hold a credential, as a database URL does, so those
// words count only right after the keyword, and a URL with a password in it
// is taken under any name (AUTH_URL=https://admin:...@host).
//
// Anything else is still a secret's name: secretKey, tokenValue,
// SECRET_KEY_BASE, API_TOKEN_SECRET, passwordHash.
var (
	wordsAfterKeyword = map[string]bool{
		"name": true, "ref": true, "izer": true, "domain": true, "row": true, "id": true, "type": true, "file": true,
		"path": true, "url": true, "uri": true, "endpoint": true, "count": true, "expiry": true, "ttl": true,
	}
	wordsEndingName = map[string]bool{
		"name": true, "ref": true, "domain": true, "row": true, "id": true, "type": true, "count": true, "expiry": true, "ttl": true,
	}
)

// namesNoSecret reports whether the name that the keyword keys[at] sits in says
// its value is something other than the secret. The last keyword of the name
// is the one whose rest is read: bearer_token_file is a file because of what
// follows token, and token_file_password is a password. keys are in the order
// of where they end.
func namesNoSecret(data []byte, keys []keywordHit, at int) bool {
	end := nameEnd(data, keys[at].end)
	from := keys[at].end
	for _, later := range keys[at+1:] {
		if later.end > end {
			break
		}
		from = later.end
	}
	// "password=" ends its name itself: what follows it is the value.
	if from == 0 || !isIdentByte(data[from-1]) {
		return false
	}
	return describesNoSecret(data[from:end])
}

// describesNoSecret reports whether the rest of a name, after the keyword in
// it, says that the value is something other than the secret.
func describesNoSecret(rest []byte) bool {
	i := 0
	// AUTH0 and OAUTH2 are the keyword still.
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	var first, last []byte
	for i < len(rest) {
		word := nameWord(rest[i:])
		if len(word) == 0 {
			i++ // a separator, or a digit inside the name
			continue
		}
		i += len(word)
		// secrets_path and credentialsFile: the plural is the keyword's.
		if first == nil && len(word) == 1 && lowerTable[word[0]] == 's' {
			continue
		}
		if first == nil {
			first = word
		}
		last = word
	}
	return listedWord(wordsAfterKeyword, first) || listedWord(wordsEndingName, last)
}

// nameWord is the word a name begins with, as names are written: lower case,
// upper case, or one capital and then lower case. In URLPath the last capital
// of the run begins the next word.
func nameWord(name []byte) []byte {
	upper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	lower := func(b byte) bool { return b >= 'a' && b <= 'z' }
	n := 0
	switch {
	case len(name) == 0:
	case lower(name[0]):
		for n < len(name) && lower(name[n]) {
			n++
		}
	case upper(name[0]):
		for n < len(name) && upper(name[n]) {
			n++
		}
		switch {
		case n == 1:
			for n < len(name) && lower(name[n]) {
				n++
			}
		case n < len(name) && lower(name[n]):
			n--
		}
	}
	return name[:n]
}

// listedWord looks a word up whatever its case, and in the plural too.
func listedWord(words map[string]bool, word []byte) bool {
	if len(word) == 0 || len(word) > 16 {
		return false
	}
	var buffer [16]byte
	for i, b := range word {
		buffer[i] = lowerTable[b]
	}
	text := buffer[:len(word)]
	if words[string(text)] {
		return true
	}
	return len(text) > 2 && text[len(text)-1] == 's' && words[string(text[:len(text)-1])]
}

// imageTag reports a container image and its tag, registry/path/name:tag, with
// the keyword in the name, as in quay.io/acme/auth-proxy:v7.6.0-alpine3.19. The
// name is the last part of a path and the tag follows its colon at once, in a
// tag's own characters. After // the same shape is the user of a URL instead,
// https://x-access-token:<token>@host, and that is a credential.
func imageTag(data []byte, keyStart, nameEnd, valueStart, valueEnd int) bool {
	if nameEnd >= len(data) || data[nameEnd] != ':' || valueStart != nameEnd+1 {
		return false
	}
	begin := keyStart
	for begin > 0 && keyStart-begin < 64 && isIdentByte(data[begin-1]) {
		begin--
	}
	if begin == 0 || data[begin-1] != '/' || (begin > 1 && data[begin-2] == '/') {
		return false
	}
	for _, b := range data[valueStart:valueEnd] {
		if !isIdentByte(b) {
			return false
		}
	}
	return true
}

// dottedToken is a token written as three runs of base64url characters joined
// by dots, 20 or more characters in all, as a Discord bot token is. The ignore
// patterns would take it for a dotted name such as config.auth.token whenever
// no part of it holds a '-'. A name it is not: its parts hold digits in more
// than one place, which a chain of identifiers hardly ever does.
func dottedToken(value []byte) bool {
	parts, characters, digitRuns := 1, 0, 0
	inDigits, partLength := false, 0
	for _, b := range value {
		digit := b >= '0' && b <= '9'
		switch {
		case b == '.':
			if partLength == 0 {
				return false
			}
			parts, partLength, inDigits = parts+1, 0, false
			continue
		case !digit && b != '-' && !isWordByte(b):
			return false
		}
		if digit && !inDigits {
			digitRuns++
		}
		inDigits = digit
		partLength++
		characters++
	}
	return parts == 3 && partLength > 0 && characters >= 20 && digitRuns >= 2
}

// pathKeyword is the shell's working directory variable (PWD, OLDPWD), which
// shares its name with the pwd= of a connection string.
func pathKeyword(word []byte) bool {
	return len(word) >= 3 && equalLower(word[:3], []byte("pwd"))
}

// looksLikePath is a filesystem path: absolute, home-relative, relative with a
// leading dot, or a Windows drive.
func looksLikePath(value []byte) bool {
	switch {
	case len(value) == 0:
		return false
	case value[0] == '/' || value[0] == '\\':
		return true
	case value[0] == '~' && (len(value) == 1 || value[1] == '/' || value[1] == '\\'):
		return true
	case value[0] == '.' && len(value) > 1 && (value[1] == '/' || value[1] == '.'):
		return true
	case len(value) > 2 && lowerTable[value[0]] >= 'a' && lowerTable[value[0]] <= 'z' && value[1] == ':' && (value[2] == '\\' || value[2] == '/'):
		return true
	}
	return false
}

// wholeValue is the string itself when it is one token, for a JSON value whose key
// is a keyword.
func wholeValue(data []byte, minLength int) (int, int, bool) {
	start, end := 0, len(data)
	for start < end && (data[start] == ' ' || data[start] == '\t') {
		start++
	}
	for end > start && (data[end-1] == ' ' || data[end-1] == '\t') {
		end--
	}
	if end-start < minLength || end-start > 512 {
		return 0, 0, false
	}
	for _, b := range data[start:end] {
		if !isValueByte(b) {
			return 0, 0, false
		}
	}
	return start, end, true
}

// plausibleSecret drops what is plainly not a value: words and identifiers,
// which have no digit.
func plausibleSecret(value []byte) bool {
	var digit, letter bool
	for _, b := range value {
		switch {
		case b >= '0' && b <= '9':
			digit = true
		case lowerTable[b] >= 'a' && lowerTable[b] <= 'z':
			letter = true
		}
	}
	return digit && letter
}

// harmlessShape is a git commit hash, a UUID or an inline image: high entropy, and
// next to words like "token" often enough, but not secrets.
func harmlessShape(value []byte) bool {
	text := string(value)
	switch {
	case len(text) == 40 && isLowerHex(text):
		return true
	case len(text) == 36 && text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-' && isLowerHex(strings.ReplaceAll(strings.ToLower(text), "-", "")):
		return true
	case strings.HasPrefix(text, "sha256:") || strings.HasPrefix(text, "sha512-") || strings.HasPrefix(text, "data:image/"):
		return true
	}
	return false
}

func isLowerHex(text string) bool {
	for i := 0; i < len(text); i++ {
		if !(text[i] >= '0' && text[i] <= '9' || text[i] >= 'a' && text[i] <= 'f') {
			return false
		}
	}
	return true
}

// validators check a format's own structure or checksum where it has one. They
// are pure and cheap: no network, no allocation worth the name. A validator that
// passes adds to a candidate's score and one that fails takes nothing away (see
// Rules.score), so none of them needs to be certain of a format to be useful.
var validators = map[string]func([]byte) bool{
	"phase-token": func(value []byte) bool {
		parts := strings.Split(string(value), ":")
		if len(parts) != 6 {
			return false
		}
		for _, part := range parts[2:] {
			if len(part) != 64 || !isLowerHex(part) {
				return false
			}
		}
		return true
	},
	"aws_key_id":    awsKeyID,
	"github_crc32":  githubChecksum,
	"npm_crc32":     npmChecksum,
	"pypi_macaroon": pypiMacaroon,
	// The names two of them had at first, for a rule file written then.
	"aws-key-id":      awsKeyID,
	"github-checksum": githubChecksum,
	"jwt": func(value []byte) bool {
		parts := strings.Split(string(value), ".")
		if len(parts) != 3 {
			return false
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
		var fields map[string]any
		return json.Unmarshal(header, &fields) == nil && fields["alg"] != nil
	},
	"pem-der": func(value []byte) bool {
		text := strings.ReplaceAll(string(value), `\n`, "\n")
		lines := strings.Split(text, "\n")
		var body strings.Builder
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "-----") {
				body.WriteString(line)
			}
		}
		der, err := base64.StdEncoding.DecodeString(body.String())
		return err == nil && len(der) > 2 && der[0] == 0x30
	},
}

// awsKeyID checks an AWS access key id: after the four-character prefix come 16
// characters of base32 (A-Z and 2-7), which decode to ten bytes.
func awsKeyID(value []byte) bool {
	if len(value) != 20 {
		return false
	}
	var decoded [10]byte
	n, err := base32.StdEncoding.Decode(decoded[:], value[4:])
	return err == nil && n == len(decoded)
}

// githubChecksum checks a GitHub token of the shape introduced in 2021: a
// three-letter prefix, an underscore, 30 random base62 characters and a
// checksum of six. Any other shape, such as the longer installation tokens,
// has no checksum this knows and is not validated.
func githubChecksum(value []byte) bool {
	return len(value) == 40 && value[0] == 'g' && value[1] == 'h' && value[3] == '_' && crc32Base62(value[4:34], value[34:])
}

// npmChecksum checks an npm access token, npm_ and then the same 30 and six.
func npmChecksum(value []byte) bool {
	return len(value) == 40 && string(value[:4]) == "npm_" && crc32Base62(value[4:34], value[34:])
}

// crc32Base62 reports whether checksum is the CRC-32 (IEEE) of body written as
// GitHub and npm write it: in base62 with the digits 0-9, A-Z, a-z, the most
// significant first, padded on the left with 0 to six characters.
//
// GitHub's own description (github.blog, "Behind GitHub's new authentication
// token formats", 2021) names CRC32, Base62 and the zero padding and stops
// there. That the sum is taken over the 30 characters before it, and this digit
// order, come from implementations and documents that follow it; the vectors in
// the tests are theirs.
func crc32Base62(body, checksum []byte) bool {
	if len(checksum) != 6 {
		return false
	}
	sum := crc32.ChecksumIEEE(body)
	for i := len(checksum) - 1; i >= 0; i-- {
		if checksum[i] != base62Alphabet[sum%62] {
			return false
		}
		sum /= 62
	}
	return sum == 0
}

// pypiMacaroonHeader is how a PyPI token's macaroon begins once decoded:
// version 2, then the location field (type 1, eight bytes long) "pypi.org".
const pypiMacaroonHeader = "\x02\x01\x08pypi.org"

// pypiMacaroon checks a PyPI upload token: after pypi- the body is base64url
// that decodes, to a version 2 macaroon whose location is pypi.org and whose
// next field is the identifier every macaroon has.
func pypiMacaroon(value []byte) bool {
	const prefix = "pypi-"
	if len(value) <= len(prefix) || string(value[:len(prefix)]) != prefix {
		return false
	}
	body := bytes.TrimRight(value[len(prefix):], "=")
	var decoded [768]byte
	if base64.RawURLEncoding.DecodedLen(len(body)) > len(decoded) {
		return false
	}
	n, err := base64.RawURLEncoding.Decode(decoded[:], body)
	if err != nil || n <= len(pypiMacaroonHeader)+2 || string(decoded[:len(pypiMacaroonHeader)]) != pypiMacaroonHeader {
		return false
	}
	// The identifier: field type 2, its length, and that many bytes.
	const identifierField = 2
	field, length := decoded[len(pypiMacaroonHeader)], int(decoded[len(pypiMacaroonHeader)+1])
	return field == identifierField && length > 0 && length < 0x80 && len(pypiMacaroonHeader)+2+length <= n
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62(n uint32, width int) string {
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = base62Alphabet[n%62]
		n /= 62
	}
	return string(out)
}
