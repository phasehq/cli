package censor

import (
	"bytes"
	"slices"
	"sort"
	"unicode/utf8"
)

// Bytes whose length must not change: a protobuf message, where every length
// is written down somewhere else in the message, or any other binary body. A
// placeholder of another length cannot be put into them, so what is found is
// overwritten where it sits (see the package documentation).

const (
	// maxBinaryDepth is how deep messages inside messages are followed, which
	// is as deep as protobuf decoders commonly go. What lies deeper is scanned
	// as one leaf.
	maxBinaryDepth = 100
	// maxBinaryRounds is how often one call looks again at what it changed.
	// The second look nearly always finds nothing; each further one is for a
	// value that came apart into pieces the matcher finds one at a time.
	maxBinaryRounds = 8
	// maxFieldNumber is the largest field number protobuf has.
	maxFieldNumber = 1<<29 - 1

	// placeholderPad fills an extent longer than its placeholder.
	placeholderPad = '*'
	// minPlaceholder is the shortest text taken for a placeholder that was
	// written earlier: the shortest extent the matcher's own minimum allows.
	minPlaceholder = chunkSize
	maxIdentifier  = 64
	maxRuleDigits  = 10
	// idWindow is how far past an id this index does not know the matcher
	// reads, to find a value that begins inside what reads as the id.
	idWindow = 512

	// maxTextView is the longest message that is also read as one string. A
	// string that only happens to parse as a message is short.
	maxTextView = 4096
)

var placeholderLead = []byte("ph:")

// placeholderTypes are the types Phase gives the values it registers. Text
// that begins ph:<one of these>: is a placeholder even when no value of the
// type has been registered with this index, as after a restart of the process
// that holds it.
var placeholderTypes = []string{"secret", "sealed", "dynamic"}

// RewriteBinary scans bytes whose length must not change and overwrites what
// it finds where it sits, so the result is exactly as long as the input and
// every byte outside a replaced extent is the input's.
//
// The input is read as a protobuf message without a schema. A length-delimited
// field whose bytes parse completely as a well-formed message is descended
// into; any other is a leaf, and each leaf is scanned on its own, so a match
// never crosses a field boundary and never takes in a tag or a length. Input
// that does not parse as a message is scanned whole, as one leaf. Leaves under
// 12 bytes hold nothing the matcher can find. A short message that is also
// text is read as one string as well, for a value that lies across what read
// as its fields (see view).
//
// An extent is overwritten with its placeholder followed by '*' up to the
// extent's length, with the placeholder alone when the two are equally long,
// and with as much of the start of the placeholder as fits when the extent is
// the shorter. In a leaf that is UTF-8 an extent that begins or ends inside a
// character is widened to the character's edge first, and one that reaches
// into a character the leaf's end cuts stops before it (see settleExtents).
// Where the matcher takes a whole base64 or hex run, the whole run is one
// extent.
//
// A second call on the output changes nothing: placeholders and their padding
// are never matched again, and one call looks again at what it changed until
// a look changes nothing (see run).
//
// Only Rules and BinaryMinLength of the options apply: a leaf has no key name.
// The report's Strings counts the leaves looked at. The returned bytes are
// data itself when nothing changed.
func (ix *Index) RewriteBinary(data []byte, opts ScanOptions) ([]byte, *Report) {
	return ix.rewriteBinary(data, opts, nil)
}

// rewriteBinary is RewriteBinary; overwritten, when set, is told of every
// range that was written to.
func (ix *Index) rewriteBinary(data []byte, opts ScanOptions, overwritten func(start, end int)) ([]byte, *Report) {
	report := &Report{}
	if len(data) < chunkSize {
		return data, report
	}
	binaryMin := opts.BinaryMinLength
	if binaryMin == 0 {
		binaryMin = binaryMinBlock
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	w := &binaryWalk{ix: ix, rules: ix.rulesFor(opts), binaryMin: binaryMin, report: report, state: newScanState(), cur: data, overwritten: overwritten}
	w.run()
	report.Changed = w.owned
	return w.cur, report
}

// binaryWalk is one call's walk.
type binaryWalk struct {
	ix        *Index
	rules     *Rules
	binaryMin int
	report    *Report
	state     *scanState

	// cur is what is being rewritten: the input until the first byte changes,
	// then a copy of it.
	cur   []byte
	owned bool

	round int
	// wrote is the leaves and viewed messages this round wrote to. changed is
	// those of the round before, in order, when this round looks only at them.
	wrote, changed [][2]int
	partial        bool

	// types are the first parts a placeholder of this index can have.
	types       []string
	overwritten func(start, end int)
}

// extent is a range to overwrite, and what was found there.
type extent struct {
	start, end int
	hit        hit
}

// run walks the input, and walks what it changed again until a walk changes
// nothing. That is what makes a second call on the result change nothing: the
// last walk of this call is the first walk of that one.
//
// A later walk looks only at the fields the one before wrote to. Leaving the
// rest out is sound as long as a field's scan depends on its bytes alone, and
// the one thing fields share is the budget for inflating compressed data. When
// that budget got low it may have decided what a scan found, so the walks are
// then done over, each with a budget of its own and each over everything.
func (w *binaryWalk) run() {
	alone := false
	for w.round = 0; w.round < maxBinaryRounds; w.round++ {
		if alone {
			w.state = newScanState()
		}
		w.partial = w.round > 0 && !alone
		w.wrote = nil
		w.node(0, len(w.cur), 0, textRead{}, false)
		low := w.state.inflateLeft < maxInflate
		switch {
		case len(w.wrote) == 0 && (w.round == 0 || alone || !low):
			return
		case low && !alone:
			alone = true
		default:
			w.changed = mergeRanges(w.wrote)
		}
	}
}

func mergeRanges(ranges [][2]int) [][2]int {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	merged := ranges[:1]
	for _, next := range ranges[1:] {
		if last := &merged[len(merged)-1]; next[0] <= last[1] {
			last[1] = max(last[1], next[1])
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

// touched reports whether the round before wrote inside a range.
func (w *binaryWalk) touched(start, end int) bool {
	i := sort.Search(len(w.changed), func(i int) bool { return w.changed[i][1] > start })
	return i < len(w.changed) && w.changed[i][0] < end
}

// textRead is what looking for text found once: cur[from:bad] reads as text,
// and the byte at bad, when there is one, does not. Fields inside that range
// take their answer from it, so no byte is looked at twice for this however
// the fields are nested.
type textRead struct {
	from, bad int
	known     bool
}

// node handles the bytes of one field, or the whole input: a message is
// descended into, anything else is a leaf. viewed says a message above this
// one is being read as a string, which covers this one.
func (w *binaryWalk) node(start, end, depth int, read textRead, viewed bool) {
	if end-start < chunkSize || (w.partial && !w.touched(start, end)) {
		return
	}
	if depth >= maxBinaryDepth || !isProtoMessage(w.cur[start:end]) {
		w.leaf(start, end)
		return
	}
	if !viewed && end-start <= maxTextView {
		text := false
		switch {
		case !read.known || start < read.from || start > read.bad:
			bad := firstNonText(w.cur[start:end])
			if text = bad < 0; text {
				bad = end - start
			}
			read = textRead{from: start, bad: start + bad, known: true}
		case end <= read.bad:
			// Inside text: text itself when it begins and ends between two
			// characters.
			text = utf8.RuneStart(w.cur[start]) && (end == len(w.cur) || end == read.bad || utf8.RuneStart(w.cur[end]))
		}
		if text {
			// Before its fields are scanned: afterwards a value that lies
			// across them would be in pieces.
			w.view(start, end, depth)
			viewed = true
		}
	}
	for at := start; at < end; {
		field, _ := readProtoField(w.cur[start:end], at-start)
		if field.wire == protoBytes {
			w.node(start+field.start, start+field.end, depth+1, read, viewed)
		}
		at = start + field.end
	}
}

// leaf scans one leaf and overwrites what was found in it.
func (w *binaryWalk) leaf(start, end int) {
	if w.round == 0 {
		w.report.Strings++
	}
	if w.binaryMin > 0 && isBinaryBlock(w.cur[start:end], w.binaryMin) {
		if w.round == 0 {
			w.report.SkippedBinary++
		}
		return
	}
	changed := false
	for _, found := range w.extents(start, end) {
		changed = w.write(found, nil) || changed
	}
	if changed {
		// All of it: a leaf that parses as a message once it is written to is
		// read field by field next, and none of those was read on its own.
		w.wrote = append(w.wrote, [2]int{start, end})
	}
}

// view reads a message that is also text as the one string it may be. A short
// string of letters and digits parses as a message often enough: a 20-character
// key id does about once in forty. Scanned field by field, a value that is
// such a string is looked for in the pieces between what happen to read as
// its tags, and missed. So it is read as a string too, for what only a string
// can hold: a value lying across what read as its fields. That is overwritten
// except in the bytes that make it a message: the tags, the lengths and the
// varints of more than one byte. Whichever of the two it is, it still parses
// as it did, and all but those bytes of the value are gone.
func (w *binaryWalk) view(start, end, depth int) {
	found, layout := w.proof(start, end, depth)
	changed := false
	for _, found := range found {
		if w.write(found, layout.free[found.start-start:found.end-start]) {
			w.report.add(found.hit)
			changed = true
		}
	}
	if changed {
		w.wrote = append(w.wrote, [2]int{start, end})
	}
}

// viewLayout is a viewed message's leaves, in order, read once for the view:
// asking the message again for every match made a view cost its square.
type viewLayout struct {
	start  int
	leaves [][2]int
	// free marks the bytes no tag, length or longer varint is made of: ASCII
	// written there leaves every field number, wire type and length as it was.
	free []bool
	// rules is what the rules find in a leaf read from one place on, by that
	// place, so no leaf is read twice for one view.
	rules map[int][]rep
}

func (w *binaryWalk) layout(start, end, depth int) *viewLayout {
	layout := &viewLayout{start: start, free: make([]bool, end-start)}
	w.lay(layout, start, end, depth)
	return layout
}

func (w *binaryWalk) lay(layout *viewLayout, start, end, depth int) {
	for at := start; at < end; {
		field, ok := readProtoField(w.cur[start:end], at-start)
		if !ok {
			return
		}
		valueStart, valueEnd := start+field.start, start+field.end
		at = valueEnd
		switch {
		case field.wire == protoBytes && depth+1 < maxBinaryDepth && isProtoMessage(w.cur[valueStart:valueEnd]):
			w.lay(layout, valueStart, valueEnd, depth+1)
			continue
		case field.wire == protoBytes:
			layout.leaves = append(layout.leaves, [2]int{valueStart, valueEnd})
		case field.wire == protoVarintType && valueEnd-valueStart > 1:
			// Its last byte is the one without the high bit: none may change.
			continue
		}
		for i := valueStart; i < valueEnd; i++ {
			layout.free[i-layout.start] = true
		}
	}
}

// leaf returns the leaf that holds the byte at, or an empty range at it when
// that byte is part of a tag, a length or a number.
func (l *viewLayout) leaf(at int) (int, int) {
	i := sort.Search(len(l.leaves), func(i int) bool { return l.leaves[i][1] > at })
	if i < len(l.leaves) && l.leaves[i][0] <= at {
		return l.leaves[i][0], l.leaves[i][1]
	}
	return at, at
}

// ruleFindsAt reports whether the rule finds something at a place when the
// leaf that holds it is read on its own from stretch on, as its own scan does.
func (w *binaryWalk) ruleFindsAt(layout *viewLayout, stretch, leafEnd, at int, rule string) bool {
	alone, read := layout.rules[stretch]
	if !read {
		_, _, alone = w.ix.rulePass(w.cur[stretch:leafEnd], "", w.rules)
		if layout.rules == nil {
			layout.rules = map[int][]rep{}
		}
		layout.rules[stretch] = alone
	}
	for _, other := range alone {
		if stretch+other.start == at && other.hit.rule == rule {
			return true
		}
	}
	return false
}

// proof returns what in the message at cur[start:end], read as one string,
// can only be a value that lies across its fields:
//
//   - the bytes of an indexed value that verified, without what the matcher
//     adds around them for good measure, when they are not inside one leaf.
//     No real message holds twelve bytes of a registered value across a tag;
//   - what a regex rule matched, when the rule finds nothing at that place in
//     the leaf the match begins in. A token at the end of a real string whose
//     pattern runs on over the next field's tag is not one: the leaf's own
//     scan takes that token.
//
// A value after a keyword and a run that only decodes to a value are no
// proof: where they end is a guess. The ranges are in order, apart, and end
// at character edges; cur[start:end] is text. The layout is set when anything
// was found.
func (w *binaryWalk) proof(start, end, depth int) ([]extent, *viewLayout) {
	var found []extent
	var layout *viewLayout
	leafOf := func(at int) (int, int) {
		if layout == nil {
			layout = w.layout(start, end, depth)
		}
		return layout.leaf(at)
	}
	block := func(from, to int) {
		if to-from < chunkSize {
			return
		}
		data := w.cur[from:to]
		for _, s := range w.ix.findSpans(data) {
			form := &w.ix.forms[s.form]
			first, last := s.checked-s.verified*chunkSize, s.checked
			switch {
			case s.full && !form.wholeRun:
				first, last = s.start, s.end
			case s.full:
				last += form.tailLen
			}
			if _, leafEnd := leafOf(from + first); leafEnd < from+last {
				found = append(found, extent{start: from + first, end: from + last, hit: w.ix.hitFor(s)})
			}
		}
		if w.rules == nil {
			return
		}
		_, _, reps := w.ix.rulePass(data, "", w.rules)
		for _, r := range reps {
			if r.hit.placeholder == "" || w.rules.afterKeyword(r.hit.rule) {
				continue
			}
			leafStart, leafEnd := leafOf(from + r.start)
			if leafEnd >= from+r.end || (leafEnd > from+r.start && w.ruleFindsAt(layout, max(leafStart, from), leafEnd, from+r.start, r.hit.rule)) {
				continue
			}
			found = append(found, extent{start: from + r.start, end: from + r.end, hit: r.hit})
		}
	}
	from := start
	for _, placed := range w.placeholders(start, end) {
		block(from, placed[0])
		from = placed[1]
	}
	block(from, end)
	sort.SliceStable(found, func(i, j int) bool { return found[i].start < found[j].start })
	return settleExtents(w.cur, start, end, found), layout
}

// afterKeyword reports whether the rule with this id takes the value after a
// keyword.
func (r *Rules) afterKeyword(id string) bool {
	for _, rule := range r.keywordRules {
		if rule.ID == id {
			return true
		}
	}
	return false
}

// extents returns what scanning cur[start:end] as one leaf finds to
// overwrite, in order and apart, and notes everything the scan finds.
// Placeholders written earlier, by this call or by an earlier one whose
// output came back, are left out of the scan: each stretch between them is
// scanned on its own, so nothing reads a placeholder or across one.
func (w *binaryWalk) extents(start, end int) []extent {
	var found []extent
	from := start
	for _, placed := range w.placeholders(start, end) {
		found = w.block(from, placed[0], found)
		from = placed[1]
	}
	return settleExtents(w.cur, start, end, w.block(from, end, found))
}

// settleExtents makes ranges found in data[start:end], in order, ready to
// overwrite. A range the matcher cut inside a character would leave half of
// it, so in bytes that are UTF-8 each is widened to the character's edge;
// ranges that meet after that become one. A range that reaches into a last
// character the leaf's end cuts stops before it (see textEnd).
func settleExtents(data []byte, start, end int, found []extent) []extent {
	if len(found) == 0 {
		return nil
	}
	if text := textEnd(data[start:end]); text >= 0 {
		text += start
		kept := found[:0]
		for _, next := range found {
			for next.start > start && next.start < text && !utf8.RuneStart(data[next.start]) {
				next.start--
			}
			next.end = min(next.end, text)
			for next.end < text && !utf8.RuneStart(data[next.end]) {
				next.end++
			}
			if next.start < next.end {
				kept = append(kept, next)
			}
		}
		if found = kept; len(found) == 0 {
			return nil
		}
	}
	apart := found[:1]
	for _, next := range found[1:] {
		if last := &apart[len(apart)-1]; next.start < last.end {
			last.end = max(last.end, next.end)
			continue
		}
		apart = append(apart, next)
	}
	return apart
}

// textEnd returns how much of data is UTF-8: all, or all but a last character
// its end cuts, as a field of a string that parses as a message can end; else -1.
func textEnd(data []byte) int {
	if utf8.Valid(data) {
		return len(data)
	}
	for cut := len(data) - 1; cut >= 0 && cut >= len(data)-(utf8.UTFMax-1); cut-- {
		if utf8.RuneStart(data[cut]) {
			if !utf8.FullRune(data[cut:]) && utf8.Valid(data[:cut]) {
				return cut
			}
			break
		}
	}
	return -1
}

// block scans one stretch that holds no placeholder: indexed values first,
// then the pattern rules over what lies between those.
func (w *binaryWalk) block(start, end int, found []extent) []extent {
	if end-start < chunkSize {
		return found
	}
	data := w.cur[start:end]
	_, hits, reps := w.ix.inventoryPass(data, 0, w.state)
	w.note(hits)
	last := 0
	rules := func(to int) {
		if w.rules == nil || to-last < chunkSize {
			return
		}
		_, ruleHits, ruleReps := w.ix.rulePass(data[last:to], "", w.rules)
		w.note(ruleHits)
		for _, r := range ruleReps {
			// A match that only alerts overwrites nothing.
			if r.hit.placeholder != "" {
				found = append(found, extent{start: start + last + r.start, end: start + last + r.end, hit: r.hit})
			}
		}
	}
	for _, r := range reps {
		if r.start < last {
			if r.end > last {
				found[len(found)-1].end, last = start+r.end, r.end
			}
			continue
		}
		rules(r.start)
		found = append(found, extent{start: start + r.start, end: start + r.end, hit: r.hit})
		last = r.end
	}
	rules(len(data))
	return found
}

func (w *binaryWalk) note(hits []hit) {
	for _, h := range hits {
		w.report.add(h)
	}
}

// write overwrites an extent with its placeholder: the placeholder and then
// padding, or as much of the placeholder as fits. free, when set, limits it
// to the marked bytes, and to characters all of whose bytes are marked: the
// placeholder is then spelled by those bytes, in order, around the ones that
// stay. It reports whether any byte changed.
func (w *binaryWalk) write(found extent, free []bool) bool {
	placeholder := found.hit.placeholder
	changed := false
	written := 0
	for at := found.start; at < found.end; {
		size := 1
		if free != nil {
			_, size = utf8.DecodeRune(w.cur[at:found.end])
			whole := true
			for i := at; i < at+size; i++ {
				whole = whole && free[i-found.start]
			}
			if !whole {
				at += size
				continue
			}
		}
		for ; size > 0; at, size, written = at+1, size-1, written+1 {
			b := byte(placeholderPad)
			if written < len(placeholder) {
				b = placeholder[written]
			}
			if w.cur[at] == b {
				continue
			}
			if !w.owned {
				w.cur, w.owned = bytes.Clone(w.cur), true
			}
			w.cur[at], changed = b, true
		}
	}
	if changed && w.overwritten != nil {
		w.overwritten(found.start, found.end)
	}
	return changed
}

// placeholders finds the placeholders already standing in cur[start:end].
func (w *binaryWalk) placeholders(start, end int) [][2]int {
	data := w.cur[start:end]
	var placed [][2]int
	for at := 0; at+minPlaceholder <= len(data); {
		i := bytes.Index(data[at:], placeholderLead)
		if i < 0 {
			break
		}
		i += at
		if length, whole := w.placeholderLength(data[i:]); whole {
			placed = append(placed, [2]int{start + i, start + i + length})
			at = i + length
			continue
		}
		at = i + len(placeholderLead)
	}
	return placed
}

// placeholderLength is how much of text, which begins "ph:", is a placeholder
// as write leaves one: ph:<type>:<id> or ph:<label>:<n> with any padding after
// it, the id perhaps cut short, or the start of one cut short inside its type.
// The type has to be one this index writes, so that text which merely holds
// "ph:" (a name ending in ph before a colon, then a password) is not taken for
// one and left unread. It says whether that is a placeholder: one as long as
// the shortest extent, or ph:<type>: with a value where its id would begin,
// which the rules read only when it is not handed to them after that.
func (w *binaryWalk) placeholderLength(text []byte) (int, bool) {
	rest := text[len(placeholderLead):]
	name := 0
	for name < len(rest) && name < maxIdentifier && identifierByte(rest[name]) {
		name++
	}
	if name < len(rest) && rest[name] == ':' && w.writesType(rest[:name]) {
		n, value := name+1, false
		if typ := string(rest[:name]); w.valueType(typ) {
			id, cut := w.idLength(typ, rest[n:])
			n, value = n+id, cut
		} else {
			// A rule numbers what it finds: digits, and nothing else.
			for digits := 0; n < len(rest) && digits < maxRuleDigits && rest[n] >= '0' && rest[n] <= '9'; n, digits = n+1, digits+1 {
			}
		}
		for n < len(rest) && rest[n] == placeholderPad {
			n++
		}
		return len(placeholderLead) + n, value || len(placeholderLead)+n >= minPlaceholder
	}
	longest := 0
	for _, known := range w.knownTypes() {
		shared := 0
		for shared < len(known) && shared < len(rest) && known[shared] == rest[shared] {
			shared++
		}
		longest = max(longest, shared)
	}
	return len(placeholderLead) + longest, len(placeholderLead)+longest >= minPlaceholder
}

// valueType reports whether a placeholder's first part is the type of an
// indexed value, whose id is a name, and not a rule's label.
func (w *binaryWalk) valueType(name string) bool {
	_, indexed := w.ix.types[name]
	return indexed || slices.Contains(placeholderTypes, name)
}

// idLength is how much of rest, after ph:<type>:, is the id, and whether a
// value ended it. A value right after a placeholder is not part of its id.
func (w *binaryWalk) idLength(typ string, rest []byte) (int, bool) {
	run := 0
	// An id cut short may be followed by the next placeholder.
	for run < len(rest) && run < maxIdentifier && identifierByte(rest[run]) && !bytes.HasPrefix(rest[run:], placeholderLead) {
		run++
	}
	// A registered id ends where it ends, whatever follows it.
	for n := run; n > 0; n-- {
		if _, registered := w.ix.secrets[secretKey{typ: typ, id: string(rest[:n])}]; registered {
			return n, false
		}
	}
	if run == 0 {
		return 0, false
	}
	// Unknown to this index, or cut short: it ends where a value begins.
	whole := run
	window := rest[:min(len(rest), run+idWindow)]
	for _, s := range w.ix.findSpans(window) {
		run = min(run, s.start)
	}
	if w.rules != nil {
		_, _, reps := w.ix.rulePass(window, "", w.rules)
		for _, r := range reps {
			if r.hit.placeholder != "" {
				run = min(run, r.start)
			}
		}
	}
	return run, run < whole
}

func identifierByte(b byte) bool {
	return b == '_' || b == '.' || b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func (w *binaryWalk) writesType(name []byte) bool {
	for _, known := range w.knownTypes() {
		if string(name) == known {
			return true
		}
	}
	return false
}

// knownTypes lists what a placeholder of this index can begin with after
// "ph:": the types of its values and the labels of its rules. It is worked
// out the first time a call meets "ph:", which most never do.
func (w *binaryWalk) knownTypes() []string {
	if w.types != nil {
		return w.types
	}
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			w.types = append(w.types, name)
		}
	}
	for _, name := range placeholderTypes {
		add(name)
	}
	for _, rules := range []*Rules{w.ix.rules, w.rules} {
		if rules == nil {
			continue
		}
		for _, rule := range rules.list {
			add(rule.Label)
		}
		for _, rule := range rules.keywordRules {
			add(rule.Label)
		}
	}
	for i := range w.ix.owners {
		add(w.ix.owners[i].typ)
	}
	return w.types
}

// firstNonText returns where data stops reading as text: the first control
// character other than a tab or a line end, or the first byte that is not
// UTF-8. It returns -1 for data that is text throughout.
func firstNonText(data []byte) int {
	for i := 0; i < len(data); {
		b := data[i]
		if b < utf8.RuneSelf {
			if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b == 0x7f {
				return i
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			return i
		}
		i += size
	}
	return -1
}

// Protobuf wire types (protobuf.dev/programming-guides/encoding). Groups, the
// two types no schema has used for years, are not read: a message that holds
// one does not parse here and is scanned as a leaf.
const (
	protoVarintType = 0
	protoFixed64    = 1
	protoBytes      = 2
	protoFixed32    = 5
)

// protoField is one field of a message: its wire type and where its value
// sits, which for a length-delimited field is the payload. The next field
// begins where the value ends.
type protoField struct {
	wire       int
	start, end int
}

// readProtoField reads the field that begins at data[at]. It reports false
// for anything a protobuf decoder would refuse.
func readProtoField(data []byte, at int) (protoField, bool) {
	tag, size := protoVarint(data[at:])
	if size == 0 || tag>>3 == 0 || tag>>3 > maxFieldNumber {
		return protoField{}, false
	}
	at += size
	field := protoField{wire: int(tag & 7), start: at}
	switch field.wire {
	case protoVarintType:
		_, size := protoVarint(data[at:])
		if size == 0 {
			return protoField{}, false
		}
		field.end = at + size
	case protoFixed64:
		field.end = at + 8
	case protoFixed32:
		field.end = at + 4
	case protoBytes:
		length, size := protoVarint(data[at:])
		if size == 0 || length > uint64(len(data)-at-size) {
			return protoField{}, false
		}
		field.start = at + size
		field.end = field.start + int(length)
	default:
		return protoField{}, false
	}
	if field.end > len(data) {
		return protoField{}, false
	}
	return field, true
}

// protoVarint decodes a varint and returns how many bytes it took, 0 when
// data does not begin with one.
func protoVarint(data []byte) (uint64, int) {
	var value uint64
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		if i == 9 && b > 1 {
			return 0, 0
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, i + 1
		}
	}
	return 0, 0
}

// isProtoMessage reports whether data parses, from its first byte to its
// last, as the fields of one message. It reads tags and lengths only, so it
// costs a step per field, not per byte.
func isProtoMessage(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for at := 0; at < len(data); {
		field, ok := readProtoField(data, at)
		if !ok {
			return false
		}
		at = field.end
	}
	return true
}
