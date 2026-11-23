package censor

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A token's regex nearly always begins with literal text: "ghp_", "sk-ant-",
// "AKIA" or "ASIA". Such a rule is tried only where one of its beginnings is
// found, and one pass over the text finds the beginnings of every rule and the
// keywords together, so a rule costs nothing on text that does not hold its
// prefix, however many rules there are.

const (
	maxStartLiterals = 64      // more beginnings than this and the rule is not anchored
	maxStartClass    = 16      // a character class larger than this ends a beginning
	maxStartBytes    = 48      // a beginning is not followed further than this
	maxBoundedMatch  = 1 << 20 // a longer match counts as unbounded

	// A beginning is followed through a choice (gh[pousr]_, sk-(?:proj|admin)-)
	// while that is worth more literals to look for: always while it is under
	// shortStartBytes, and through a choice of at most smallChoice while it is
	// under enoughStartBytes.
	shortStartBytes  = 4
	enoughStartBytes = 8
	smallChoice      = 4
)

// startLiteral is text a rule's match can begin with. A folded one is compared
// the way the regex compares it, by simple case folding.
type startLiteral struct {
	text string
	fold bool
}

// prefixSet is what a regex node's match can begin with. When exact is set each
// literal is all the node matches, so whatever follows the node extends it.
type prefixSet struct {
	lits  []startLiteral
	exact bool
}

// unknownPrefix is a node whose beginning is not followed: anything may come.
func unknownPrefix() prefixSet { return prefixSet{lits: []startLiteral{{}}} }

// startLiterals lists the literals one of which every match of the regex begins
// with. It reports false when there is no such list: the regex can begin with
// too many things, or with nothing fixed, or with under two bytes.
func startLiterals(tree *syntax.Regexp) ([]startLiteral, bool) {
	lits := prefixesOf(tree).lits
	sort.Slice(lits, func(i, j int) bool {
		if lits[i].text != lits[j].text {
			return lits[i].text < lits[j].text
		}
		return !lits[i].fold && lits[j].fold
	})
	var out []startLiteral
	for _, lit := range lits {
		if minEncodedLength(lit) < 2 {
			return nil, false
		}
		// A literal that only continues one already kept adds nothing: wherever
		// it is found, so is the shorter one.
		covered := false
		for _, kept := range out {
			covered = covered || (kept.fold == lit.fold && strings.HasPrefix(lit.text, kept.text))
		}
		if !covered {
			out = append(out, lit)
		}
	}
	if len(out) == 0 || len(out) > maxStartLiterals {
		return nil, false
	}
	return out, true
}

// minEncodedLength is the fewest bytes the literal can take in the text: a
// folded rune may be written with a shorter one of its case variants.
func minEncodedLength(lit startLiteral) int {
	if !lit.fold {
		return len(lit.text)
	}
	total := 0
	for _, r := range lit.text {
		shortest := utf8.RuneLen(r)
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			shortest = min(shortest, utf8.RuneLen(f))
		}
		total += shortest
	}
	return total
}

func prefixesOf(re *syntax.Regexp) prefixSet {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return prefixSet{lits: []startLiteral{{}}, exact: true}
	case syntax.OpLiteral:
		fold := false
		for i, r := range re.Rune {
			// The regex takes U+FFFD for any invalid byte too, which no literal
			// comparison would.
			if r == utf8.RuneError {
				return prefixSet{lits: []startLiteral{{text: string(re.Rune[:i]), fold: fold}}}
			}
			if re.Flags&syntax.FoldCase != 0 && unicode.SimpleFold(r) != r {
				fold = true
			}
		}
		return prefixSet{lits: []startLiteral{{text: string(re.Rune), fold: fold}}, exact: true}
	case syntax.OpCharClass:
		count := 0
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi-lo >= maxStartClass || (lo <= utf8.RuneError && utf8.RuneError <= hi) {
				return unknownPrefix()
			}
			count += int(hi-lo) + 1
		}
		if count == 0 || count > maxStartClass {
			return unknownPrefix()
		}
		set := prefixSet{exact: true}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				set.lits = append(set.lits, startLiteral{text: string(r)})
			}
		}
		return set
	case syntax.OpCapture:
		return prefixesOf(re.Sub[0])
	case syntax.OpConcat:
		set := prefixSet{lits: []startLiteral{{}}, exact: true}
		for _, sub := range re.Sub {
			if !set.exact {
				break
			}
			next := prefixesOf(sub)
			product, ok := extend(set.lits, next.lits)
			if !ok || !worthFollowing(shortest(set.lits), len(next.lits)) {
				set.exact = false
				break
			}
			set = prefixSet{lits: product, exact: next.exact}
		}
		return set
	case syntax.OpAlternate:
		set := prefixSet{exact: true}
		for _, sub := range re.Sub {
			next := prefixesOf(sub)
			set.lits = append(set.lits, next.lits...)
			set.exact = set.exact && next.exact
			if len(set.lits) > maxStartLiterals {
				return unknownPrefix()
			}
		}
		return set
	case syntax.OpQuest:
		return optional(prefixesOf(re.Sub[0]))
	case syntax.OpPlus:
		set := prefixesOf(re.Sub[0])
		set.exact = false
		return set
	case syntax.OpRepeat:
		set := prefixesOf(re.Sub[0])
		switch {
		case re.Min == 1 && re.Max == 1:
			return set
		case re.Min == 0 && re.Max == 1:
			return optional(set)
		case re.Min >= 1:
			set.exact = false
			return set
		}
		return unknownPrefix()
	}
	return unknownPrefix()
}

// worthFollowing says whether beginnings of the given length should be followed
// through a choice of so many continuations. Long ones are rare in text as they
// are, and following them would only make more of them to look for.
func worthFollowing(length, choices int) bool {
	return choices <= 1 || length < shortStartBytes || (choices <= smallChoice && length < enoughStartBytes)
}

func shortest(lits []startLiteral) int {
	n := maxStartBytes
	for _, lit := range lits {
		n = min(n, len(lit.text))
	}
	return n
}

// optional is a node that may also match nothing.
func optional(set prefixSet) prefixSet {
	return prefixSet{lits: append([]startLiteral{{}}, set.lits...), exact: set.exact}
}

// extend follows every literal of a with every literal of b. It reports false
// when that makes too many, or too long, to be worth following.
func extend(a, b []startLiteral) ([]startLiteral, bool) {
	if len(a)*len(b) > maxStartLiterals {
		return nil, false
	}
	out := make([]startLiteral, 0, len(a)*len(b))
	for _, head := range a {
		for _, tail := range b {
			if len(head.text)+len(tail.text) > maxStartBytes {
				return nil, false
			}
			out = append(out, startLiteral{text: head.text + tail.text, fold: head.fold || tail.fold})
		}
	}
	return out, true
}

// maxMatchLength is the most bytes a match of the regex can take, or 0 when
// there is no bound.
func maxMatchLength(re *syntax.Regexp) int {
	n, bounded := matchLength(re)
	if !bounded || n > maxBoundedMatch {
		return 0
	}
	return n
}

func matchLength(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		total := 0
		for _, r := range re.Rune {
			// A folded rune can be written with a longer case variant.
			if re.Flags&syntax.FoldCase != 0 {
				total += utf8.UTFMax
				continue
			}
			total += encodedLength(r)
		}
		return total, true
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0, true
		}
		// The ranges are in order, so the last holds the longest rune.
		return encodedLength(re.Rune[len(re.Rune)-1]), true
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, true
	case syntax.OpCapture, syntax.OpQuest:
		return matchLength(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, false
		}
		n, bounded := matchLength(re.Sub[0])
		if !bounded || n*re.Max > maxBoundedMatch {
			return 0, false
		}
		return n * re.Max, true
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			n, bounded := matchLength(sub)
			if !bounded || total+n > maxBoundedMatch {
				return 0, false
			}
			total += n
		}
		return total, true
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			n, bounded := matchLength(sub)
			if !bounded {
				return 0, false
			}
			longest = max(longest, n)
		}
		return longest, true
	}
	// OpStar, OpPlus and anything this does not know.
	return 0, false
}

// encodedLength is the most bytes a rune up to r takes in UTF-8.
func encodedLength(r rune) int {
	if n := utf8.RuneLen(r); n > 0 {
		return n
	}
	return utf8.UTFMax
}

// literalSet finds, in one pass over a block, every keyword and every place a
// rule's match could begin. A table of the byte pairs a literal can begin with
// filters each offset, and the byte after the pair filters most of what is
// left, so the pass costs a lookup per byte and a comparison only where a
// literal is likely.
type literalSet struct {
	buckets  []literalBucket
	keywords bool            // keywords are found in the same pass
	table    [1 << 16]uint16 // by two bytes: 1 + the bucket of the literals beginning with them
}

type literalBucket struct {
	third [4]uint64 // a bit for every byte that follows the pair in one of the literals
	lits  []literal
}

type literal struct {
	text  []byte // compared as it is, or (a keyword) with ASCII letters lowered
	runes []rune // set for a folded literal, which is compared rune by rune instead
	rule  int32  // index of the rule that can begin here, or -1 for a keyword
}

// opening is the first bytes of one way a literal can be written: three of
// them, or two when that is all of it.
type opening struct {
	bytes [3]byte
	n     int
}

// startHit is a place a rule's match could begin.
type startHit struct {
	pos  int
	rule int32
}

// newLiteralSet indexes the beginnings of the given rules and, when words is
// set, its keywords. It returns nil when there is nothing to find.
func newLiteralSet(words *keywordSet, rules []*Rule) *literalSet {
	l := &literalSet{keywords: !words.empty()}
	add := func(openings []opening, lit literal) {
		placed := map[uint16]bool{}
		for _, open := range openings {
			key := uint16(open.bytes[0])<<8 | uint16(open.bytes[1])
			if l.table[key] == 0 {
				// The table's entries can count this far and no further; past it,
				// pairs share the last bucket, whose literals are compared in full.
				if len(l.buckets) < 1<<16-1 {
					l.buckets = append(l.buckets, literalBucket{})
				}
				l.table[key] = uint16(len(l.buckets))
			}
			bucket := &l.buckets[l.table[key]-1]
			if !placed[l.table[key]] {
				placed[l.table[key]] = true
				bucket.lits = append(bucket.lits, lit)
			}
			if open.n < 3 {
				bucket.third = [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
				continue
			}
			bucket.third[open.bytes[2]>>6] |= 1 << (open.bytes[2] & 63)
		}
	}
	// Keywords go in first and in their own order: several can begin at one
	// place, and they are reported in the order the keyword set reports them.
	if l.keywords {
		for _, word := range words.words {
			add(asciiOpenings(word), literal{text: word, rule: -1})
		}
	}
	for i, rule := range rules {
		for _, start := range rule.starts {
			lit := literal{text: []byte(start.text), rule: int32(i)}
			if start.fold {
				lit.runes = []rune(start.text)
				add(foldOpenings(lit.runes), lit)
				continue
			}
			add([]opening{openingOf(start.text)}, lit)
		}
	}
	if len(l.buckets) == 0 {
		return nil
	}
	return l
}

func openingOf(text string) opening {
	var open opening
	open.n = copy(open.bytes[:], text)
	return open
}

// asciiOpenings are the ways the first bytes of a keyword can be written: a
// keyword is lowercase, and matches whatever the case of its ASCII letters.
func asciiOpenings(word []byte) []opening {
	openings := []opening{{}}
	for i := 0; i < len(word) && i < 3; i++ {
		variants := []byte{word[i]}
		if word[i] >= 'a' && word[i] <= 'z' {
			variants = append(variants, word[i]-32)
		}
		var next []opening
		for _, open := range openings {
			for _, variant := range variants {
				open.bytes[i], open.n = variant, i+1
				next = append(next, open)
			}
		}
		openings = next
	}
	return openings
}

// foldOpenings are the ways the first bytes of a folded literal can be written,
// over every case variant of its first runes.
func foldOpenings(runes []rune) []opening {
	heads := []string{""}
	for i := 0; i < len(runes) && i < 3; i++ {
		var next []string
		for _, head := range heads {
			// Three bytes are all an opening holds.
			if len(head) >= 3 {
				next = append(next, head)
				continue
			}
			for _, variant := range foldOrbit(runes[i]) {
				next = append(next, head+string(variant))
			}
		}
		heads = next
	}
	seen := map[opening]bool{}
	var openings []opening
	for _, head := range heads {
		if open := openingOf(head); !seen[open] {
			seen[open] = true
			openings = append(openings, open)
		}
	}
	return openings
}

// foldOrbit is a rune with its case variants.
func foldOrbit(r rune) []rune {
	orbit := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	return orbit
}

// hasFoldPrefix reports whether data begins with the runes under simple case
// folding, which is how a case-insensitive regex compares them.
func hasFoldPrefix(data []byte, runes []rune) bool {
	for _, want := range runes {
		if len(data) == 0 {
			return false
		}
		r, size := rune(data[0]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(data)
		}
		if r != want && !foldEqual(r, want) {
			return false
		}
		data = data[size:]
	}
	return true
}

func foldEqual(a, b rune) bool {
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}

// scan returns every keyword occurrence, ordered by where it ends as
// keywordSet.find orders them, and every place a rule could begin, in order.
func (l *literalSet) scan(data []byte) ([]keywordHit, []startHit) {
	var keys []keywordHit
	var starts []startHit
	sorted := true
	for i := 0; i+1 < len(data); i++ {
		index := l.table[uint16(data[i])<<8|uint16(data[i+1])]
		if index == 0 {
			continue
		}
		bucket := &l.buckets[index-1]
		// At the last pair of the block there is no third byte: only a literal
		// of two bytes can be there, and the comparison below sees to that.
		if i+2 < len(data) {
			if next := data[i+2]; bucket.third[next>>6]&(1<<(next&63)) == 0 {
				continue
			}
		}
		rest := data[i:]
		for k := range bucket.lits {
			lit := &bucket.lits[k]
			switch {
			case lit.rule < 0:
				if len(lit.text) <= len(rest) && equalLower(rest[:len(lit.text)], lit.text) {
					end := i + len(lit.text)
					sorted = sorted && (len(keys) == 0 || keys[len(keys)-1].end <= end)
					keys = append(keys, keywordHit{start: i, end: end})
				}
			case lit.runes != nil:
				if hasFoldPrefix(rest, lit.runes) {
					starts = append(starts, startHit{pos: i, rule: lit.rule})
				}
			default:
				if len(lit.text) <= len(rest) && string(rest[:len(lit.text)]) == string(lit.text) {
					starts = append(starts, startHit{pos: i, rule: lit.rule})
				}
			}
		}
	}
	// find sorts by end; hits come out in that order already unless one keyword
	// reaches past the start of another, and sorting what is sorted changes nothing.
	if !sorted {
		sort.Slice(keys, func(a, b int) bool { return keys[a].end < keys[b].end })
	}
	return keys, starts
}
