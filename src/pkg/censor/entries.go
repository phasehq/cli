package censor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// EntriesVersion is the only version of Entries this package reads and writes.
const EntriesVersion = 1

const (
	chunkSize        = 12
	macSize          = 16
	minValueLength   = 12
	minValueEntropy  = 2.5 // bits per byte
	weakChunkEntropy = 2.8
	leafMinLength    = 20

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
	Version int    `json:"v"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Forms   []Form `json:"forms"`
	// Unprotected lists what was not indexed, and why. A value with no Forms is
	// not protected at all.
	Unprotected []Unprotected `json:"unprotected,omitempty"`
}

// Form is one encoded form of a value (or of one part of it), cut into
// non-overlapping chunks of 12 bytes.
type Form struct {
	// Part is empty for the value itself, "url-password" for a URL's password or
	// the token that is its user, and "leaf:<n>" for the n-th string leaf of a
	// JSON value.
	Part   string `json:"part,omitempty"`
	Form   string `json:"form"`
	Length int    `json:"len"`
	Rolls  []byte `json:"rolls"`          // the keyed rolling hash of each chunk, 8 bytes little-endian each
	MACs   []byte `json:"macs"`           // the keyed SHA-256 of each chunk, truncated to 16 bytes each
	Weak   []byte `json:"weak"`           // a bit per chunk, low bit first: structure, never a partial hit alone
	Tail   []byte `json:"tail,omitempty"` // the keyed SHA-256 of the bytes after the last whole chunk
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

// IndexValue indexes a value under key. typ is a short word such as "secret" and
// id an opaque identifier; both become the placeholder ph:<typ>:<id> and must
// match [A-Za-z0-9_.-]{1,64}. Nothing in the result is derived from the value
// except keyed hashes and lengths. A value too short, too plain or too long to
// protect gives Entries with no Forms and the reason in Unprotected.
func IndexValue(key *Key, typ, id, value string) (*Entries, error) {
	if key == nil {
		return nil, errors.New("indexing a value needs a key")
	}
	if err := checkIdentifiers(typ, id); err != nil {
		return nil, err
	}
	b := &entriesBuilder{key: key, entries: &Entries{Version: EntriesVersion, Type: typ, ID: id}}
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
			part := partLeafPrefix + strconv.Itoa(i)
			if looksPublic(l.value) {
				b.skip(part, ReasonPublicLeaf)
				continue
			}
			// Short leaves are labels such as "service_account" or a domain name,
			// which turn up in ordinary text.
			if len(l.value) < leafMinLength {
				b.skip(part, ReasonShortLeaf)
				continue
			}
			b.addValue(part, l.value)
			if credential := urlCredential(l.value); credential != "" {
				b.addValue(part, credential)
			}
		}
		// Numbers are not indexed next to strings. Those that look like key
		// material are listed, so that it is not silent.
		for n := keyNumbers(value); n > 0 && len(b.entries.Unprotected) < maxUnprotected; n-- {
			b.skip("", ReasonNumbers)
		}
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
		b.addForm(part, candidate, decoy)
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
			b.addForm(part, rawForm{name: formLine, bytes: []byte(line)}, nil)
		}
	}
}

func (b *entriesBuilder) addForm(part string, candidate rawForm, decoy []byte) {
	c := chunkSize
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
		Rolls:  make([]byte, 0, 8*n),
		MACs:   make([]byte, 0, macSize*n),
		Weak:   make([]byte, (n+7)/8),
	}
	for i := 0; i < n; i++ {
		chunk := candidate.bytes[i*c : (i+1)*c]
		if entropy(string(chunk)) < weakChunkEntropy || (decoy != nil && string(decoy[i*c:(i+1)*c]) == string(chunk)) {
			f.Weak[i/8] |= 1 << (i % 8)
		}
		f.Rolls = binary.LittleEndian.AppendUint64(f.Rolls, b.key.roll(chunk))
		mac := b.key.mac(chunk)
		f.MACs = append(f.MACs, mac[:]...)
	}
	if tail := candidate.bytes[n*c:]; len(tail) > 0 {
		mac := b.key.mac(tail)
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
	if e.Version != EntriesVersion {
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
		if _, ok := formShapes[f.Form]; !ok {
			return fmt.Errorf("form %d: unknown form %q", i, truncate(f.Form))
		}
		if f.Length < chunkSize || f.Length > maxFormLength {
			return fmt.Errorf("form %d: length %d is out of bounds", i, f.Length)
		}
		n := f.Length / chunkSize
		if len(f.Rolls) != 8*n || len(f.MACs) != macSize*n || len(f.Weak) != (n+7)/8 {
			return fmt.Errorf("form %d: chunk data does not match its length", i)
		}
		if n%8 != 0 && f.Weak[len(f.Weak)-1]>>(n%8) != 0 {
			return fmt.Errorf("form %d: weak flags past the last chunk", i)
		}
		if hasTail := f.Length%chunkSize != 0; (hasTail && len(f.Tail) != macSize) || (!hasTail && len(f.Tail) != 0) {
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
