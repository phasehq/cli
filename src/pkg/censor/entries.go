package censor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// EntriesVersion is the matching scheme IndexValue writes: the current one.
// Entries of every scheme in SupportedSchemes are read and matched. The
// package documentation says what a scheme version covers and when it changes.
const EntriesVersion = 2

const (
	// chunkSize is the chunk of scheme 1, and the smallest of any scheme: no
	// shorter text can hold a chunk.
	chunkSize        = 12
	macSize          = 16
	minValueLength   = 12
	minValueEntropy  = 2.5 // bits per byte
	weakChunkEntropy = 2.8
	leafMinLength    = 20
	// lookupBits is how much of a chunk's rolling hash scheme 2 keeps: a bit more
	// is one a holder of the key need not guess, a bit less doubles wasted hashes.
	lookupBits = 24

	// MaxValueLength is the longest value IndexValue indexes. Every form of a
	// value is indexed, so a value costs about thirty times its length in chunks.
	MaxValueLength = 64 << 10

	maxFormLength     = 4 * MaxValueLength // the longest form a value of MaxValueLength can have
	maxFormsPerValue  = 4096
	maxChunksPerValue = 1 << 18
	maxUnprotected    = 4096
	maxEntriesBytes   = 64 << 20
)

// Reasons a value, or a part of one, is not protected.
const (
	ReasonTooShort    = "too short to protect"
	ReasonLowEntropy  = "too little entropy to protect"
	ReasonTooLong     = "too long to protect"
	ReasonShortLeaf   = "too short for a leaf"
	ReasonPublicLeaf  = "looks public (a URL, an email address or a certificate)"
	ReasonNumbers     = "numbers, which are not indexed next to strings"
	partURLPassword   = "url-password"
	partLeafPrefix    = "leaf:"
	maxReasonLength   = 128
	maxPartLength     = 16
	identifierPattern = `^[A-Za-z0-9_.-]{1,64}$`
)

var identifier = regexp.MustCompile(identifierPattern)

var knownReasons = map[string]bool{
	ReasonTooShort: true, ReasonLowEntropy: true, ReasonTooLong: true, ReasonShortLeaf: true, ReasonPublicLeaf: true,
	ReasonNumbers: true,
}

// Entries is what indexing one value produces: keyed hashes and their layout,
// never the value. A client that decrypts a value builds Entries with IndexValue
// and the daemon's Key, and sends them to the daemon, which adds them to its
// Index without seeing the value.
type Entries struct {
	// Version is the matching scheme the entries were built under.
	Version int    `json:"v"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Forms   []Form `json:"forms"`
	// Unprotected lists what was not indexed, and why. A value with no Forms is
	// not protected at all.
	Unprotected []Unprotected `json:"unprotected,omitempty"`
}

// Form is one encoded form of a value (or of one part of it), cut into
// non-overlapping chunks: of 12 bytes, or of 24 when it is Wide.
type Form struct {
	// Part is empty for the value itself, "url-password" for a URL's password or
	// the token that is its user, and "leaf:<n>" for the n-th string leaf of a
	// JSON value or the n-th value of text that is names and values.
	Part   string `json:"part,omitempty"`
	Form   string `json:"form"`
	Length int    `json:"len"`
	// Wide says the chunks are 24 bytes, as scheme 2 cuts a form made of hex
	// digits and the base64 of a value made of hex digits.
	Wide bool `json:"wide,omitempty"`
	// Rolls is scheme 1's keyed rolling hash of each chunk, whole: 8 bytes
	// little-endian each. Later schemes leave it empty and fill Lookups.
	Rolls []byte `json:"rolls,omitempty"`
	// Lookups is the top 24 bits of each chunk's rolling hash, 3 bytes
	// big-endian each: enough to find a chunk by, not enough to work it out.
	Lookups []byte `json:"lookups,omitempty"`
	MACs    []byte `json:"macs"`           // the keyed SHA-256 of each chunk, truncated to 16 bytes each
	Weak    []byte `json:"weak"`           // a bit per chunk, low bit first: structure, never a partial hit alone
	Tail    []byte `json:"tail,omitempty"` // the keyed SHA-256 of the bytes after the last whole chunk; from scheme 2, of that chunk and them
}

// Unprotected is a value, or part of one, that was not indexed.
type Unprotected struct {
	Part   string `json:"part,omitempty"`
	Reason string `json:"reason"`
}

// Protected reports whether anything of the value was indexed.
func (e *Entries) Protected() bool { return e != nil && len(e.Forms) > 0 }

// Placeholder is what replaces the value in a request.
func (e *Entries) Placeholder() string { return "ph:" + e.Type + ":" + e.ID }

// IndexValue indexes a value under key: its lookup key for the lookup values,
// its confirming key for the hashes that confirm. typ is a short word such as "secret" and
// id an opaque identifier; both become the placeholder ph:<typ>:<id> and must
// match [A-Za-z0-9_.-]{1,64}. Nothing in the result is derived from the value
// except keyed hashes and lengths. A value too short, too plain or too long to
// protect gives Entries with no Forms and the reason in Unprotected.
func IndexValue(key *Key, typ, id, value string) (*Entries, error) {
	return indexValue(key, schemes[EntriesVersion], typ, id, value)
}

func indexValue(key *Key, s *scheme, typ, id, value string) (*Entries, error) {
	if key == nil {
		return nil, errors.New("indexing a value needs a key")
	}
	if err := checkIdentifiers(typ, id); err != nil {
		return nil, err
	}
	macKey := key.macFor(s)
	if macKey == nil {
		return nil, errors.New("indexing a value under this scheme needs a confirming key")
	}
	b := &entriesBuilder{key: key, macKey: macKey, scheme: s, entries: &Entries{Version: s.version, Type: typ, ID: id}}
	value = strings.TrimSpace(value)
	if len(value) > MaxValueLength {
		b.skip("", ReasonTooLong)
		return b.entries, nil
	}
	// A JSON document such as a service account key is mostly structure and
	// public fields, so each string leaf is protected on its own. Leaves are
	// named by position, not by key, so no part of the document leaves here.
	if leaves := jsonLeaves(value); len(leaves) > 0 {
		for i, l := range leaves {
			// Short leaves are labels such as "service_account" or a domain name,
			// which turn up in ordinary text.
			b.addLeaf(partLeafPrefix+strconv.Itoa(i), l.value, leafMinLength)
		}
		// Numbers are not indexed next to strings. Those that look like key
		// material are listed, so that it is not silent.
		for n := keyNumbers(value); n > 0 && len(b.entries.Unprotected) < maxUnprotected; n-- {
			b.skip("", ReasonNumbers)
		}
		return b.finish()
	}
	// So is text that is names and values, such as a kubeconfig or an env file.
	if b.addStructured(value) {
		return b.finish()
	}
	b.addValue("", value)
	// A URL's password, or the token that is its user, is also protected on its
	// own, in every encoding.
	if credential := urlCredential(value); credential != "" {
		b.addValue(partURLPassword, credential)
	}
	return b.finish()
}

type entriesBuilder struct {
	key     *Key
	macKey  *[32]byte
	scheme  *scheme
	entries *Entries
	chunks  int
}

func (b *entriesBuilder) skip(part, reason string) {
	b.entries.Unprotected = append(b.entries.Unprotected, Unprotected{Part: part, Reason: reason})
}

func (b *entriesBuilder) finish() (*Entries, error) {
	if len(b.entries.Forms) > maxFormsPerValue || b.chunks > maxChunksPerValue || len(b.entries.Unprotected) > maxUnprotected {
		return nil, errors.New("the value has too many parts to index")
	}
	return b.entries, nil
}

func (b *entriesBuilder) addValue(part, value string) {
	if len(value) < minValueLength {
		b.skip(part, ReasonTooShort)
		return
	}
	if entropy(value) < minValueEntropy {
		b.skip(part, ReasonLowEntropy)
		return
	}
	// A decoy that differs from the value only where the value isn't structure
	// marks the chunks that hold nothing secret: they come out the same in both.
	forms := encodedForms(value)
	var decoys []rawForm
	if mask := weakMask(value); mask != nil {
		decoys = encodedForms(decoyOf(value, mask))
		if len(decoys) != len(forms) {
			decoys = nil
		}
	}
	// The form bytes only live for the length of this call.
	seenForm := map[string]bool{}
	for i, candidate := range forms {
		if seenForm[string(candidate.bytes)] {
			continue
		}
		seenForm[string(candidate.bytes)] = true
		var decoy []byte
		if decoys != nil {
			decoy = decoys[i].bytes
		}
		b.addForm(part, value, candidate, decoy)
	}
	if strings.Contains(value, "\n") {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			// Armour lines are the same in every PEM block and hold nothing secret,
			// and a line of words, as apiVersion: v1 in a kubeconfig, would be
			// replaced wherever it is written.
			if strings.HasPrefix(line, "-----") || len(line) < minValueLength || entropy(line) < minValueEntropy || !secretLine(line) {
				continue
			}
			if seenForm[line] {
				continue
			}
			seenForm[line] = true
			b.addForm(part, line, rawForm{name: formLine, bytes: []byte(line)}, nil)
		}
	}
}

func (b *entriesBuilder) addForm(part, value string, candidate rawForm, decoy []byte) {
	c, wide := b.scheme.chunkFor(candidate, value)
	if len(candidate.bytes) < c {
		return
	}
	if len(decoy) != len(candidate.bytes) {
		decoy = nil
	}
	n := len(candidate.bytes) / c
	f := Form{
		Part:   part,
		Form:   candidate.name,
		Length: len(candidate.bytes),
		Wide:   wide,
		MACs:   make([]byte, 0, macSize*n),
		Weak:   make([]byte, (n+7)/8),
	}
	for i := 0; i < n; i++ {
		chunk := candidate.bytes[i*c : (i+1)*c]
		if entropy(string(chunk)) < weakChunkEntropy || (decoy != nil && string(decoy[i*c:(i+1)*c]) == string(chunk)) {
			f.Weak[i/8] |= 1 << (i % 8)
		}
		b.scheme.appendLookup(&f, b.key.roll(chunk))
		mac := mac(b.macKey, chunk)
		f.MACs = append(f.MACs, mac[:]...)
	}
	if tail := candidate.bytes[n*c:]; len(tail) > 0 {
		mac := mac(b.macKey, candidate.bytes[n*c-b.scheme.tailBack(c):])
		f.Tail = mac[:]
	}
	b.chunks += n
	b.entries.Forms = append(b.entries.Forms, f)
}

func checkIdentifiers(typ, id string) error {
	if !identifier.MatchString(typ) {
		return fmt.Errorf("type %q must be 1 to 64 of A-Z, a-z, 0-9, '_', '.' and '-'", truncate(typ))
	}
	if !identifier.MatchString(id) {
		return fmt.Errorf("id %q must be 1 to 64 of A-Z, a-z, 0-9, '_', '.' and '-'", truncate(id))
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// Marshal encodes the entries for sending to the daemon.
func (e *Entries) Marshal() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// ParseEntries decodes and validates entries received from a client. Unknown
// fields, trailing data, another version and anything out of bounds are refused.
func ParseEntries(data []byte) (*Entries, error) {
	if len(data) > maxEntriesBytes {
		return nil, errors.New("entries are too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var e Entries
	if err := decoder.Decode(&e); err != nil {
		return nil, fmt.Errorf("entries are not valid: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("entries are not valid: trailing data")
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// validate checks everything the index relies on, since entries arrive from a
// process the daemon does not trust.
func (e *Entries) validate() error {
	if e == nil {
		return errors.New("no entries")
	}
	s := schemes[e.Version]
	if s == nil {
		return fmt.Errorf("entries version %d is not supported", e.Version)
	}
	if err := checkIdentifiers(e.Type, e.ID); err != nil {
		return err
	}
	if len(e.Forms) > maxFormsPerValue {
		return fmt.Errorf("entries have %d forms, more than %d", len(e.Forms), maxFormsPerValue)
	}
	if len(e.Unprotected) > maxUnprotected {
		return errors.New("entries list too many unprotected parts")
	}
	chunks := 0
	for i := range e.Forms {
		f := &e.Forms[i]
		if !validPart(f.Part) {
			return fmt.Errorf("form %d: part is not valid", i)
		}
		if _, ok := s.shapes[f.Form]; !ok {
			return fmt.Errorf("form %d: unknown form %q", i, truncate(f.Form))
		}
		c, err := s.chunkOf(f)
		if err != nil {
			return fmt.Errorf("form %d: %w", i, err)
		}
		if f.Length < c || f.Length > maxFormLength {
			return fmt.Errorf("form %d: length %d is out of bounds", i, f.Length)
		}
		n := f.Length / c
		if held, other := s.lookups(f); len(held) != s.lookupSize()*n || len(other) != 0 || len(f.MACs) != macSize*n || len(f.Weak) != (n+7)/8 {
			return fmt.Errorf("form %d: chunk data does not match its length", i)
		}
		if n%8 != 0 && f.Weak[len(f.Weak)-1]>>(n%8) != 0 {
			return fmt.Errorf("form %d: weak flags past the last chunk", i)
		}
		if hasTail := f.Length%c != 0; (hasTail && len(f.Tail) != macSize) || (!hasTail && len(f.Tail) != 0) {
			return fmt.Errorf("form %d: tail does not match its length", i)
		}
		chunks += n
	}
	if chunks > maxChunksPerValue {
		return fmt.Errorf("entries have %d chunks, more than %d", chunks, maxChunksPerValue)
	}
	for _, u := range e.Unprotected {
		if !validPart(u.Part) || !knownReasons[u.Reason] {
			return errors.New("an unprotected part is not valid")
		}
	}
	return nil
}

func validPart(part string) bool {
	if part == "" || part == partURLPassword {
		return true
	}
	if !strings.HasPrefix(part, partLeafPrefix) || len(part) > maxPartLength {
		return false
	}
	digits := part[len(partLeafPrefix):]
	if digits == "" || (len(digits) > 1 && digits[0] == '0') {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}
