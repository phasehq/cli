package censor

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash/maphash"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	cacheMinBlock  = 256      // shorter strings are cheaper to rescan than to hash and look up
	cacheMaxBytes  = 64 << 20 // the cache starts over past this
	binaryMinBlock = 16 << 10 // a base64-only string this long is an image or a file, not text
)

// ErrNotJSON is returned by RewriteJSON for a body that is not valid JSON.
var ErrNotJSON = errors.New("the body is not valid JSON")

// DefaultConversationFields are the top-level request fields that carry what the
// model reads and writes, across the provider API shapes. Key names elsewhere in
// the body are the harness's own.
var DefaultConversationFields = []string{"messages", "input", "system", "instructions", "contents", "systemInstruction", "prompt"}

var defaultConversationRoots = rootSet(DefaultConversationFields)

func rootSet(fields []string) map[string]bool {
	set := make(map[string]bool, len(fields))
	for _, field := range fields {
		set[field] = true
	}
	return set
}

// ScanOptions tune RewriteJSON. Zero values take the defaults.
type ScanOptions struct {
	// ConversationFields are the top-level fields under which a JSON key name
	// counts as a keyword for the pattern rules. Nil means
	// DefaultConversationFields. Indexed values are found everywhere regardless.
	ConversationFields []string
	// BinaryMinLength is the length from which a string made only of base64
	// characters, or a data: URI, is taken for an image or a file and skipped.
	// Zero means 16 KiB; a negative value never skips.
	BinaryMinLength int
	// Rules, when set, are the pattern rules this call applies instead of the
	// index's own, such as a subset made with Rules.Only. Indexed values are
	// found whatever it holds.
	Rules *Rules
}

// RewriteJSON scans a JSON request body and replaces what it finds in place.
// Every string value is decoded, scanned and, when anything was found,
// re-encoded; every other byte of the body is left exactly as it was. A string
// that itself holds JSON, such as tool call arguments, is walked the same way.
// The returned body is the input itself when nothing changed.
func (ix *Index) RewriteJSON(body []byte, opts ScanOptions) ([]byte, *Report, error) {
	report := &Report{JSON: true}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || !json.Valid(body) {
		return body, &Report{}, ErrNotJSON
	}
	roots := defaultConversationRoots
	if opts.ConversationFields != nil {
		roots = rootSet(opts.ConversationFields)
	}
	binaryMin := opts.BinaryMinLength
	if binaryMin == 0 {
		binaryMin = binaryMinBlock
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	w := &walker{ix: ix, data: body, report: report, top: true, roots: roots, binaryMin: binaryMin, state: newScanState(), rules: ix.rulesFor(opts)}
	w.value()
	out := body
	if len(w.reps) > 0 {
		out = w.apply()
		report.Changed = true
	}
	for _, h := range w.hits {
		report.add(h)
	}
	return out, report, nil
}

// Providers sign or encrypt some of what they hand back, and the client sends
// it again as it was: Anthropic checks a thinking block against its signature
// and refuses an edited one, which breaks every later request of the session.
// The provider wrote that text, so removing a value from it protects nothing.
// Such strings are scanned so a finding is reported, and never changed.
var (
	signedBlockTypes = map[string]bool{"thinking": true, "redacted_thinking": true}
	signedBlockKeys  = map[string]bool{"thinking": true, "signature": true, "data": true}
)

const encryptedContentKey = "encrypted_content"

type segment struct {
	key   string
	index int
	array bool
}

// walker walks JSON that is already known to be valid.
type walker struct {
	ix        *Index
	data      []byte
	pos       int
	stack     []segment
	report    *Report
	top       bool // the request body, rather than JSON found inside a string
	roots     map[string]bool
	binaryMin int
	state     *scanState
	rules     *Rules
	reps      []jsonRep // string literals to replace, in the order they were scanned
	hits      []hit
}

// jsonRep replaces the string literal at data[start:end].
type jsonRep struct {
	start, end int
	literal    []byte
}

// apply builds the rewritten bytes. A string held back until its object's type
// was known is scanned after its neighbours, so the replacements are sorted.
func (w *walker) apply() []byte {
	sort.Slice(w.reps, func(i, j int) bool { return w.reps[i].start < w.reps[j].start })
	out := make([]byte, 0, len(w.data))
	last := 0
	for _, r := range w.reps {
		out = append(out, w.data[last:r.start]...)
		out = append(out, r.literal...)
		last = r.end
	}
	return append(out, w.data[last:]...)
}

// underEncryptedContent reports a value under a key named encrypted_content.
func (w *walker) underEncryptedContent() bool {
	for _, s := range w.stack {
		if !s.array && s.key == encryptedContentKey {
			return true
		}
	}
	return false
}

// pointer is the JSON pointer (RFC 6901) of the current value.
func (w *walker) pointer() string {
	var b strings.Builder
	for _, s := range w.stack {
		b.WriteByte('/')
		if s.array {
			b.WriteString(strconv.Itoa(s.index))
			continue
		}
		b.WriteString(pointerEscaper.Replace(s.key))
	}
	return b.String()
}

var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

// keyName is the nearest object key above the current value.
func (w *walker) keyName() string {
	for i := len(w.stack) - 1; i >= 0; i-- {
		if !w.stack[i].array {
			return w.stack[i].key
		}
	}
	return ""
}

func (w *walker) ws() {
	for w.pos < len(w.data) {
		switch w.data[w.pos] {
		case ' ', '\t', '\r', '\n':
			w.pos++
		default:
			return
		}
	}
}

func (w *walker) value() {
	w.ws()
	if w.pos >= len(w.data) {
		return
	}
	switch w.data[w.pos] {
	case '{':
		w.object()
	case '[':
		w.array()
	case '"':
		start := w.pos
		end := w.str()
		w.handleString(start, end, false)
	default:
		for w.pos < len(w.data) {
			switch w.data[w.pos] {
			case ',', ']', '}', ' ', '\t', '\r', '\n':
				return
			}
			w.pos++
		}
	}
}

func (w *walker) object() {
	w.pos++
	w.ws()
	if w.data[w.pos] == '}' {
		w.pos++
		return
	}
	// Whether the object is a signed block depends on its type member, which
	// may come after the members it decides about; those wait for it.
	type held struct {
		key        string
		start, end int
	}
	var typ string
	typeKnown := false
	var waiting []held
	for {
		w.ws()
		keyStart := w.pos
		keyEnd := w.str()
		key := decodeKey(w.data[keyStart:keyEnd])
		w.ws()
		w.pos++ // ':'
		w.ws()
		w.stack = append(w.stack, segment{key: key})
		switch {
		case w.data[w.pos] == '"' && key == "type":
			start := w.pos
			end := w.str()
			typ, typeKnown = decodeKey(w.data[start:end]), true
			w.handleString(start, end, false)
		case w.data[w.pos] == '"' && signedBlockKeys[key]:
			start := w.pos
			end := w.str()
			if typeKnown {
				w.handleString(start, end, signedBlockTypes[typ])
			} else {
				waiting = append(waiting, held{key: key, start: start, end: end})
			}
		default:
			w.value()
		}
		w.stack = w.stack[:len(w.stack)-1]
		w.ws()
		if w.data[w.pos] == ',' {
			w.pos++
			continue
		}
		w.pos++ // '}'
		for _, h := range waiting {
			w.stack = append(w.stack, segment{key: h.key})
			w.handleString(h.start, h.end, signedBlockTypes[typ])
			w.stack = w.stack[:len(w.stack)-1]
		}
		return
	}
}

func (w *walker) array() {
	w.pos++
	w.ws()
	if w.data[w.pos] == ']' {
		w.pos++
		return
	}
	w.stack = append(w.stack, segment{array: true})
	for {
		w.value()
		w.ws()
		if w.data[w.pos] == ',' {
			w.pos++
			w.stack[len(w.stack)-1].index++
			continue
		}
		w.pos++ // ']'
		break
	}
	w.stack = w.stack[:len(w.stack)-1]
}

// str moves past a string literal and returns where it ends.
func (w *walker) str() int {
	i := w.pos + 1
	for {
		next := bytes.IndexAny(w.data[i:], "\"\\")
		if next < 0 {
			w.pos = len(w.data)
			return w.pos
		}
		i += next
		if w.data[i] == '\\' {
			i += 2
			continue
		}
		w.pos = i + 1
		return w.pos
	}
}

func decodeKey(literal []byte) string {
	inner := literal[1 : len(literal)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		return string(inner)
	}
	var key string
	if json.Unmarshal(literal, &key) != nil {
		return string(inner)
	}
	return key
}

// handleString scans one string literal. A signed one, in the request body
// itself, is scanned for the report only and left exactly as it was.
func (w *walker) handleString(start, end int, signed bool) {
	literal := w.data[start:end]
	inner := literal[1 : len(literal)-1]
	var text []byte
	if bytes.IndexByte(inner, '\\') < 0 {
		text = inner
	} else {
		var decoded string
		if json.Unmarshal(literal, &decoded) != nil {
			return
		}
		text = []byte(decoded)
	}
	if len(text) < chunkSize {
		return
	}
	w.report.Strings++
	if w.binaryMin > 0 && isBinaryBlock(text, w.binaryMin) {
		w.report.SkippedBinary++
		return
	}
	// The request body's own keys belong to the harness, not to anything the
	// model read: a field of its named like a credential is not a keyword hit.
	keyName := w.keyName()
	if w.top && len(w.stack) > 0 && !w.roots[w.stack[0].key] {
		keyName = ""
	}
	var entry *cacheEntry
	var key uint64
	cacheable := len(text) >= cacheMinBlock
	if cacheable {
		var hash maphash.Hash
		hash.SetSeed(cacheSeed)
		// What a string's scan finds depends on its key name, the rules the
		// call applies and, for JSON held in it, on where binary skipping starts.
		hash.WriteString(keyName)
		hash.WriteByte(0)
		hash.WriteString(strconv.Itoa(w.binaryMin))
		hash.WriteByte(0)
		hash.WriteString(strconv.FormatUint(w.rules.cacheTag(), 10))
		hash.WriteByte(0)
		hash.Write(text)
		key = hash.Sum64()
		w.report.CacheLookups++
		entry = w.ix.cache.get(key, len(text))
		if entry != nil {
			w.report.CacheHits++
		}
	}
	if entry == nil {
		entry = w.rewriteString(text, keyName)
		if cacheable {
			w.ix.cache.put(key, len(text), entry)
		}
	}
	if len(entry.hits) == 0 {
		return
	}
	// Only the request's own structure can hold what the provider signed. JSON
	// found inside a string is text a tool or a file produced, whatever its
	// keys are called, so nothing in it is exempt.
	signed = w.top && (signed || w.underEncryptedContent())
	here := w.pointer()
	for _, h := range entry.hits {
		h.path = here + h.path
		if signed && h.action == actionRedact {
			h.action = actionLeft
		}
		w.hits = append(w.hits, h)
	}
	if entry.literal != nil && !signed {
		w.reps = append(w.reps, jsonRep{start: start, end: end, literal: entry.literal})
	}
}

// rewriteString scans one decoded string. Hit paths are relative to the string;
// a hit inside JSON held in the string has the inner pointer after a '#'.
func (w *walker) rewriteString(text []byte, keyName string) *cacheEntry {
	entry := &cacheEntry{}
	trimmed := bytes.TrimSpace(text)
	if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(text) {
		nested := &walker{ix: w.ix, data: text, report: &Report{}, roots: w.roots, binaryMin: w.binaryMin, state: w.state, rules: w.rules}
		nested.value()
		w.report.Strings += nested.report.Strings
		w.report.SkippedBinary += nested.report.SkippedBinary
		w.report.CacheLookups += nested.report.CacheLookups
		w.report.CacheHits += nested.report.CacheHits
		for _, h := range nested.hits {
			h.path = "#" + h.path
			entry.hits = append(entry.hits, h)
		}
		if len(nested.reps) > 0 {
			entry.literal = encodeString(nested.apply())
		}
		return entry
	}
	out, hits, ruleHits, _, changed := w.ix.scanBlock(text, keyName, w.state, false, w.rules)
	entry.hits = append(hits, ruleHits...)
	if changed {
		entry.literal = encodeString(out)
	}
	return entry
}

func encodeString(text []byte) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(string(text))
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
}

// isBinaryBlock spots images and files carried as base64, which are skipped.
func isBinaryBlock(text []byte, minLength int) bool {
	if len(text) < minLength {
		return false
	}
	if bytes.HasPrefix(text, []byte("data:")) {
		if comma := bytes.Index(text[:min(len(text), 200)], []byte(";base64,")); comma > 0 {
			return true
		}
	}
	for _, b := range text {
		if !classRun[b] {
			return false
		}
	}
	return true
}

var cacheSeed = maphash.MakeSeed()

type cacheEntry struct {
	literal []byte // the re-encoded string literal, or nil when unchanged
	hits    []hit
}

// blockCache remembers what scanning a string found, keyed by a hash of the string,
// so the unchanged history that every request repeats isn't scanned again. It
// holds only hashes, hit metadata and already-rewritten text.
type blockCache struct {
	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
	bytes   int
}

type cacheKey struct {
	hash   uint64
	length int
}

func newBlockCache() *blockCache { return &blockCache{entries: map[cacheKey]*cacheEntry{}} }

func (c *blockCache) get(hash uint64, length int) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[cacheKey{hash, length}]
}

func (c *blockCache) put(hash uint64, length int, entry *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := 64 + len(entry.literal) + 64*len(entry.hits)
	if c.bytes+size > cacheMaxBytes {
		c.entries = map[cacheKey]*cacheEntry{}
		c.bytes = 0
	}
	c.entries[cacheKey{hash, length}] = entry
	c.bytes += size
}

func (c *blockCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[cacheKey]*cacheEntry{}
	c.bytes = 0
}
