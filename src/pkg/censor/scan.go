package censor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"sort"
)

const (
	decodeRunMin   = 24 // shortest base64 or hex run that is decoded and rescanned
	maxDecodeDepth = 2

	// Compressed data inside a decoded run is inflated to at most this much, and
	// to at most inflateRatio times its compressed size past inflateFloor, so a
	// small bomb costs little. A run that would inflate further is not scanned.
	maxInflate   = 1 << 20
	inflateFloor = 64 << 10
	inflateRatio = 256
	// inflateBudget bounds what one call inflates in total, across every run.
	inflateBudget = 16 << 20
)

const (
	kindInventory = "inventory"
	kindRule      = "rule"
	actionRedact  = "redact"
	actionAlert   = "alert"
	// actionLeft is a finding in text the provider signed or encrypted. Changing
	// it would make the provider refuse the request, and the provider wrote it.
	actionLeft = "left"
)

// hit is one place a value or a pattern was found. It never holds the value.
type hit struct {
	kind        string // inventory or rule
	placeholder string // what replaced it, empty for a rule hit that only alerts
	label       string // a rule's label
	rule        string
	action      string
	score       int
	form        string // raw, base64, hex, url, json, line, ..., or pattern
	part        string // url-password or leaf:<n> for a part of an indexed value
	decoded     bool   // found by decoding a base64 or hex run
	partial     bool   // only part of the value's extent verified
	path        string // JSON pointer in the request, relative while scanning a string
}

// rep is a found range in the coordinates of the bytes scanned, with what
// replaces it (nothing, for an alert).
type rep struct {
	start, end int
	hit        hit
}

// scanState is shared by everything one call scans.
type scanState struct {
	inflateLeft int
}

func newScanState() *scanState { return &scanState{inflateLeft: inflateBudget} }

type span struct {
	start, end int
	form       int32
	full       bool
	verified   int
	checked    int // where the verified chunks end
}

type tryKey struct {
	form  int32
	start int
}

// findSpans returns every place in data where a chunk of an indexed form verified,
// widened to as much of the form's extent as could be confirmed.
func (ix *Index) findSpans(data []byte) []span {
	c := chunkSize
	k := ix.key
	if len(data) < c || len(ix.chunks) == 0 {
		return nil
	}
	h := k.roll(data[:c])
	var tried map[tryKey]struct{}
	// covered is how far each form's verified chunks already reach. A chunk
	// inside them is part of a match already extended, so trying it again would
	// only walk the same bytes, once per repeat of a repeating value.
	var covered map[int32]int
	var spans []span
	for p := 0; ; p++ {
		if ix.bloomHas(h) {
			if refs, ok := ix.chunks[h]; ok {
				var here [macSize]byte
				hashed := false
				for _, ref := range refs {
					if end, ok := covered[ref.form]; ok && p+c <= end {
						continue
					}
					if !hashed {
						here, hashed = k.mac(data[p:p+c]), true
					}
					if here != ix.forms[ref.form].macs[ref.idx] {
						continue
					}
					if tried == nil {
						tried = map[tryKey]struct{}{}
						covered = map[int32]int{}
					}
					if found, ok := ix.try(data, p, ref, tried); ok {
						spans = append(spans, found)
						covered[ref.form] = max(covered[ref.form], found.checked)
					}
				}
			}
		}
		if p+c >= len(data) {
			break
		}
		h = (h-k.table[data[p]]*k.outPow)*k.base + k.table[data[p+c]]
	}
	return spans
}

// try works out the extent around a confirmed chunk.
//
// When only part of the extent verifies, the leak was truncated. The verified chunks
// are replaced, and so are the unverified bytes up to the edge of where the value
// would sit, as long as they could belong to it (the form's alphabet, and never a
// quote or white space). That removes the leftover partial chunk at each end, which
// the hashes can't confirm, at the cost of at most chunk-1 neighbouring bytes on
// each side when a value is followed directly by similar-looking text.
func (ix *Index) try(data []byte, p int, ref chunkRef, tried map[tryKey]struct{}) (span, bool) {
	c := chunkSize
	f := &ix.forms[ref.form]
	start := p - int(ref.idx)*c
	key := tryKey{form: ref.form, start: start}
	if _, done := tried[key]; done {
		return span{}, false
	}
	// The caller has confirmed the chunk at p.
	tried[key] = struct{}{}
	n := len(f.macs)
	lo, hi := int(ref.idx), int(ref.idx)
	for j := lo - 1; j >= 0; j-- {
		pos := start + j*c
		if pos < 0 || ix.key.mac(data[pos:pos+c]) != f.macs[j] {
			break
		}
		lo = j
	}
	for j := hi + 1; j < n; j++ {
		pos := start + j*c
		if pos+c > len(data) || ix.key.mac(data[pos:pos+c]) != f.macs[j] {
			break
		}
		hi = j
	}
	s, e := start+lo*c, start+(hi+1)*c
	full := false
	if lo == 0 && hi == n-1 {
		switch {
		case f.tailLen == 0:
			full = true
		case e+f.tailLen <= len(data) && ix.key.mac(data[e:e+f.tailLen]) == f.tail:
			e += f.tailLen
			full = true
		}
	}
	if !full {
		// A piece made only of structure, such as PEM armour or a token's type
		// prefix, says nothing about this value: every value of its kind has it.
		strong := false
		for j := lo; j <= hi && !strong; j++ {
			strong = !f.weak[j]
		}
		if !strong {
			return span{}, false
		}
		// One chunk of a base64 or hex form covers nine or six bytes of the
		// value. When those come from a small alphabet, as a hex value's do,
		// the chunk can be had by chance: text that holds base64 over hex
		// repeats such chunks. One of them alone is no match; a second
		// verified next to it settles it.
		if lo == hi && f.wholeRun && chunkBits(data[start+lo*c:start+(lo+1)*c], f.class) < minPartialBits {
			return span{}, false
		}
	}
	switch {
	case f.wholeRun:
		// A value encoded inside a larger blob, such as a dockerconfigjson or a
		// Basic auth header, takes the whole blob, so no decodable piece is left.
		for s > 0 && f.class[data[s-1]] {
			s--
		}
		for e < len(data) && f.class[data[e]] {
			e++
		}
	case full:
		for k := 0; k < f.slack && s > 0 && f.class[data[s-1]]; k++ {
			s--
		}
		for k := 0; k < f.slack && e < len(data) && f.class[data[e]]; k++ {
			e++
		}
	default:
		floor := max(start, 0)
		for s > floor && f.class[data[s-1]] {
			s--
		}
		ceiling := min(start+f.length, len(data))
		for e < ceiling && f.class[data[e]] {
			e++
		}
	}
	return span{start: s, end: e, form: ref.form, full: full, verified: hi - lo + 1, checked: start + (hi+1)*c}, true
}

// minPartialBits is the least a single verified chunk of a base64 or hex form
// has to carry of the value it encodes for a partial match to rest on it.
const minPartialBits = 48

// chunkBits estimates how many bits of a value one chunk of its base64 or hex
// form carries: the bytes the chunk encodes, times the bits a byte of their
// alphabet can hold. The chunk is text of the scanned request that a keyed
// hash has just confirmed, so nothing here is read from the index, and entries
// indexed before this was asked are held to it too. A base64 form is indexed at
// three alignments, so its chunk begins at one of three places in a byte of
// the value: the reading that carries least is taken.
func chunkBits(chunk []byte, class *[256]bool) float64 {
	if class == &classHex {
		decoded := make([]byte, hex.DecodedLen(len(chunk)))
		if _, err := hex.Decode(decoded, chunk); err != nil {
			return 8 * float64(len(chunk))
		}
		return float64(len(decoded)) * alphabetBits(decoded)
	}
	// Six bits a character, most significant first.
	var bits []byte
	for _, b := range chunk {
		value, ok := base64Value(b)
		if !ok {
			return 8 * float64(len(chunk))
		}
		for shift := 5; shift >= 0; shift-- {
			bits = append(bits, value>>shift&1)
		}
	}
	least := math.MaxFloat64
	for _, skip := range []int{0, 4, 6} {
		var decoded []byte
		for at := skip; at+8 <= len(bits); at += 8 {
			var b byte
			for _, bit := range bits[at : at+8] {
				b = b<<1 | bit
			}
			decoded = append(decoded, b)
		}
		least = math.Min(least, float64(len(bits))/8*alphabetBits(decoded))
	}
	return least
}

func base64Value(b byte) (byte, bool) {
	switch {
	case b >= 'A' && b <= 'Z':
		return b - 'A', true
	case b >= 'a' && b <= 'z':
		return b - 'a' + 26, true
	case b >= '0' && b <= '9':
		return b - '0' + 52, true
	case b == '+' || b == '-':
		return 62, true
	case b == '/' || b == '_':
		return 63, true
	}
	return 0, false
}

// alphabetBits is how many bits a byte of the alphabet these bytes are drawn
// from can hold: the digits, the letters a to f or all of them in either case,
// and punctuation, counting only the kinds that are there. Hex digits come to 4
// bits and letters and digits to nearly 6; bytes that are not printable ASCII
// count as 8.
func alphabetBits(text []byte) float64 {
	var digits, lowerHex, lower, upperHex, upper, other bool
	for _, b := range text {
		switch {
		case b >= '0' && b <= '9':
			digits = true
		case b >= 'a' && b <= 'f':
			lowerHex = true
		case b >= 'g' && b <= 'z':
			lower = true
		case b >= 'A' && b <= 'F':
			upperHex = true
		case b >= 'G' && b <= 'Z':
			upper = true
		case b >= ' ' && b < 0x7f:
			other = true
		default:
			return 8
		}
	}
	size := 0
	if digits {
		size += 10
	}
	switch {
	case lower:
		size += 26
	case lowerHex:
		size += 6
	}
	switch {
	case upper:
		size += 26
	case upperHex:
		size += 6
	}
	if other {
		size += 33
	}
	if size == 0 {
		return 8
	}
	return math.Log2(float64(size))
}

// resolve merges overlapping spans. Each group is labelled by its best span: a full
// match over a partial one, then the most verified chunks.
func resolve(spans []span) []span {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var groups []span
	for _, next := range spans {
		if len(groups) > 0 && next.start < groups[len(groups)-1].end {
			last := &groups[len(groups)-1]
			end := max(last.end, next.end)
			if better(next, *last) {
				start := last.start
				*last = next
				last.start = start
			}
			last.end = end
			continue
		}
		groups = append(groups, next)
	}
	return groups
}

func better(a, b span) bool {
	if a.full != b.full {
		return a.full
	}
	if a.verified != b.verified {
		return a.verified > b.verified
	}
	return a.end-a.start > b.end-b.start
}

func (ix *Index) hitFor(s span) hit {
	f := ix.forms[s.form]
	o := ix.owners[f.owner]
	return hit{kind: kindInventory, placeholder: o.placeholder, action: actionRedact, form: f.name, part: o.part, partial: !s.full}
}

// inventoryPass finds every indexed value in data, then decodes long base64 and
// hex runs in what is left and finds any run that hides a value. It returns the
// rewritten bytes, every hit, and the replaced ranges in data's coordinates.
func (ix *Index) inventoryPass(data []byte, depth int, st *scanState) ([]byte, []hit, []rep) {
	out := data
	var hits []hit
	var reps []rep
	var placed [][2]int // where placeholders went, so the decode pass leaves them alone
	if spans := ix.findSpans(data); len(spans) > 0 {
		groups := resolve(spans)
		var buffer bytes.Buffer
		buffer.Grow(len(data))
		last := 0
		for _, group := range groups {
			h := ix.hitFor(group)
			buffer.Write(data[last:group.start])
			at := buffer.Len()
			buffer.WriteString(h.placeholder)
			placed = append(placed, [2]int{at, buffer.Len()})
			last = group.end
			hits = append(hits, h)
			reps = append(reps, rep{start: group.start, end: group.end, hit: h})
		}
		buffer.Write(data[last:])
		out = buffer.Bytes()
	}
	if depth < maxDecodeDepth {
		if decoded, decodedHits, decodedReps, ok := ix.decodePass(out, depth, placed, st); ok {
			out = decoded
			hits = append(hits, decodedHits...)
			// Decoded runs never touch a placeholder, so each sits in bytes the
			// first pass left alone and maps back by a plain shift.
			for i := range decodedReps {
				decodedReps[i].start = mapPosition(decodedReps[i].start, reps, false)
				decodedReps[i].end = mapPosition(decodedReps[i].end, reps, true)
			}
			reps = mergeReps(reps, decodedReps)
		}
	}
	return out, hits, reps
}

// mapPosition turns a position in the rewritten bytes back into one in the bytes
// that were scanned, given the replacements made (sorted, in the scanned bytes'
// coordinates). A position inside a placeholder maps to the replaced range's
// start, or its end when end is set.
func mapPosition(pos int, reps []rep, end bool) int {
	shift := 0
	for _, r := range reps {
		if r.hit.placeholder == "" {
			continue
		}
		outStart := r.start + shift
		outEnd := outStart + len(r.hit.placeholder)
		if pos <= outStart {
			return pos - shift
		}
		if pos < outEnd {
			if end {
				return r.end
			}
			return r.start
		}
		shift += len(r.hit.placeholder) - (r.end - r.start)
	}
	return pos - shift
}

func mergeReps(a, b []rep) []rep {
	if len(b) == 0 {
		return a
	}
	merged := append(append([]rep(nil), a...), b...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].start < merged[j].start })
	return merged
}

// decodePass looks for long base64 or hex runs, decodes them and scans the result.
// A run that hides a value is replaced whole. Lines wrapped at 64 or 76 characters,
// as PEM bodies and the base64 tool write them, are joined first. A run that
// decodes to gzip or zlib data is inflated, within limits, and the result scanned.
func (ix *Index) decodePass(data []byte, depth int, placed [][2]int, st *scanState) ([]byte, []hit, []rep, bool) {
	var out []byte
	var hits []hit
	var reps []rep
	last := 0
	nextPlaced := 0
	for i := 0; i < len(data); {
		if !classRun[data[i]] || data[i] == '=' {
			i++
			continue
		}
		start := i
		var joined []byte
		for {
			lineStart := i
			for i < len(data) && classRun[data[i]] && data[i] != '=' {
				i++
			}
			for i < len(data) && data[i] == '=' {
				i++
			}
			line := data[lineStart:i]
			wrapped := (len(line) == 64 || len(line) == 76) && bytes.IndexByte(line, '=') < 0
			next := i
			if next < len(data) && data[next] == '\r' {
				next++
			}
			if wrapped && next+1 < len(data) && data[next] == '\n' && classRun[data[next+1]] && data[next+1] != '=' {
				joined = append(joined, line...)
				i = next + 1
				continue
			}
			if joined != nil {
				joined = append(joined, line...)
			}
			break
		}
		for nextPlaced < len(placed) && placed[nextPlaced][1] <= start {
			nextPlaced++
		}
		if nextPlaced < len(placed) && placed[nextPlaced][0] < i {
			continue // the run touches a placeholder
		}
		run := data[start:i]
		if joined != nil {
			run = joined
		}
		if len(run) < decodeRunMin {
			continue
		}
		decoded, kind := decodeRun(run)
		if inflated, how, ok := inflate(decoded, st); ok {
			decoded, kind = inflated, kind+">"+how
		}
		if len(decoded) < chunkSize {
			continue
		}
		_, inner, _ := ix.inventoryPass(decoded, depth+1, st)
		if len(inner) == 0 {
			continue
		}
		out = append(out, data[last:start]...)
		out = append(out, inner[0].placeholder...)
		last = i
		for j, h := range inner {
			h.decoded = true
			h.form = kind + ">" + h.form
			hits = append(hits, h)
			if j == 0 {
				reps = append(reps, rep{start: start, end: i, hit: h})
			}
		}
	}
	if len(hits) == 0 {
		return data, nil, nil, false
	}
	out = append(out, data[last:]...)
	return out, hits, reps, true
}

func decodeRun(run []byte) ([]byte, string) {
	text := string(bytes.TrimRight(run, "="))
	if len(text)%2 == 0 && isHex(text) {
		if decoded, err := hex.DecodeString(text); err == nil {
			return decoded, "hex"
		}
	}
	encoding := base64.RawStdEncoding
	if bytes.ContainsAny(run, "-_") {
		if bytes.ContainsAny(run, "+/") {
			return nil, ""
		}
		encoding = base64.RawURLEncoding
	}
	if len(text)%4 == 1 {
		text = text[:len(text)-1]
	}
	decoded, err := encoding.DecodeString(text)
	if err != nil {
		return nil, ""
	}
	return decoded, "base64"
}

func isHex(text string) bool {
	for i := 0; i < len(text); i++ {
		if !classHex[text[i]] {
			return false
		}
	}
	return true
}

// inflate decompresses gzip or zlib data, as Helm keeps a release, within the
// caps. Anything that fails or would pass a cap is reported as not inflated, so
// the run is scanned as it decoded.
func inflate(data []byte, st *scanState) ([]byte, string, bool) {
	var reader io.Reader
	var kind string
	switch {
	case len(data) >= 18 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8:
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "", false
		}
		gz.Multistream(false)
		reader, kind = gz, "gzip"
	case len(data) >= 6 && data[0]&0x0f == 8 && data[0]>>4 <= 7 && data[1]&0x20 == 0 && (uint16(data[0])<<8|uint16(data[1]))%31 == 0:
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "", false
		}
		reader, kind = zr, "zlib"
	default:
		return nil, "", false
	}
	limit := min(maxInflate, max(inflateFloor, inflateRatio*len(data)), st.inflateLeft)
	if limit <= 0 {
		return nil, "", false
	}
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	st.inflateLeft -= len(out)
	if err != nil || len(out) > limit {
		return nil, "", false
	}
	return out, kind, true
}

// scanBlock runs the inventory and then the pattern rules over one block. keyName
// is the JSON key holding it, if any, which counts as a keyword. It returns the
// rewritten bytes, the inventory and rule hits, and every found range in data's
// coordinates. Ranges can nest when a rule match spans a placeholder.
func (ix *Index) scanBlock(data []byte, keyName string, st *scanState, wantRanges bool, rules *Rules) ([]byte, []hit, []hit, []rep, bool) {
	out, hits, reps := ix.inventoryPass(data, 0, st)
	changed := len(reps) > 0
	rewritten, ruleHits, ruleReps := ix.rulePass(out, keyName, rules)
	if len(ruleReps) > 0 && wantRanges {
		inventory := reps
		reps = append([]rep(nil), inventory...)
		for _, r := range ruleReps {
			r.start = mapPosition(r.start, inventory, false)
			r.end = mapPosition(r.end, inventory, true)
			reps = append(reps, r)
		}
		sort.SliceStable(reps, func(i, j int) bool { return reps[i].start < reps[j].start })
	}
	for _, r := range ruleHits {
		if r.placeholder != "" {
			changed = true
			break
		}
	}
	return rewritten, hits, ruleHits, reps, changed
}
