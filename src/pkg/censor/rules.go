package censor

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var defaultRules []byte

// Rule finds a credential by its shape, whatever the inventory holds. A rule is a
// regex, a prefix followed by a run of characters from a charset, or (keyword_value)
// the value written right after a secret-sounding keyword, which a regex can then
// hold to one shape.
//
// Every candidate gets a score: the rule's base score, plus a bonus when a keyword
// sits just before it (or is the JSON key holding it), plus a bonus when the rule's
// validator passes, minus a penalty for documentation example values and known
// harmless shapes. At or above redact_at it is replaced, at or above alert_at it is
// recorded, and below that it is ignored. Inventory matches don't go through this:
// they always redact.
type Rule struct {
	ID           string  `yaml:"id"`
	Description  string  `yaml:"description"`
	Regex        string  `yaml:"regex"`
	Prefix       string  `yaml:"prefix"`
	Charset      string  `yaml:"charset"`
	Length       int     `yaml:"length"`
	MinLength    int     `yaml:"min_length"`
	MaxLength    int     `yaml:"max_length"`
	MinEntropy   float64 `yaml:"min_entropy"`
	Action       string  `yaml:"action"` // alert caps the rule below redaction
	Label        string  `yaml:"label"`
	Score        *int    `yaml:"score"`
	RedactAt     *int    `yaml:"redact_at"`
	AlertAt      *int    `yaml:"alert_at"`
	Validator    string  `yaml:"validator"`
	KeywordValue bool    `yaml:"keyword_value"`
	// Hints are literal strings at least one of which every match contains: the
	// rule runs only on text holding one. A regex that does not begin with a
	// literal needs them, because it runs over the whole of such text.
	Hints []string `yaml:"hints"`

	re       *regexp.Regexp
	group    int
	hints    [][]byte
	base     int
	redactAt int
	alertAt  int
	validate func([]byte) bool
	order    int // its place in the file, which settles a tie between two rules

	// Set when every match begins with one of a few literals, as a token's does
	// with its prefix: the regex is then tried only where one of them is found.
	// atStart is the regex held to the start of the bytes it is given, afterByte
	// the same with one byte of context before the match.
	starts    []startLiteral
	atStart   *regexp.Regexp
	afterByte *regexp.Regexp
	maxLen    int // the longest match in bytes, 0 when there is no bound
}

func (r *Rule) mayMatch(data []byte) bool {
	if len(r.hints) == 0 {
		return true
	}
	for _, hint := range r.hints {
		if bytes.Contains(data, hint) {
			return true
		}
	}
	return false
}

// Scoring is the rule file's shared settings.
type Scoring struct {
	Keywords         []string `yaml:"keywords"`
	KeywordWindow    int      `yaml:"keyword_window"`
	KeywordBonus     int      `yaml:"keyword_bonus"`
	ValidatorBonus   int      `yaml:"validator_bonus"`
	IgnorePenalty    int      `yaml:"ignore_penalty"`
	ShapePenalty     int      `yaml:"shape_penalty"`
	IgnoreValues     []string `yaml:"ignore_values"`
	IgnoreSubstrings []string `yaml:"ignore_substrings"`
	IgnorePatterns   []string `yaml:"ignore_patterns"`
}

// SkippedRule is a rule of a parsed file that this version cannot apply, and why.
type SkippedRule struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Rules is a compiled rule file.
type Rules struct {
	list           []*Rule // regex and prefix rules, in file order
	keywordRules   []*Rule
	unanchored     []*Rule     // the rules of list that run over the whole text
	literals       *literalSet // where the other rules of list can begin, and the keywords
	skipped        []SkippedRule
	scoring        Scoring
	keywords       *keywordSet
	ignoreValues   map[string]bool
	ignoreSubs     [][]byte
	ignorePatterns []*regexp.Regexp
	// tag tells rule sets apart in the scan cache, which is shared by every
	// call on an index whatever rules the call applies.
	tag uint64
}

var rulesTags atomic.Uint64

func (r *Rules) cacheTag() uint64 {
	if r == nil {
		return 0
	}
	return r.tag
}

// index prepares the one pass that finds where the rules can begin. It is run
// once, when the set is made: a Rules never changes afterwards.
func (r *Rules) index() {
	r.unanchored = nil
	for _, rule := range r.list {
		if rule.atStart == nil {
			r.unanchored = append(r.unanchored, rule)
		}
	}
	// Keyword positions are needed on every block only by keyword_value rules;
	// without them they are looked for when a candidate has to be scored.
	var words *keywordSet
	if len(r.keywordRules) > 0 {
		words = r.keywords
	}
	r.literals = newLiteralSet(words, r.list)
}

// Only returns the rules whose ids are given, sharing everything else. An id
// the file never had is an error, so a typo never silently drops a rule; an id
// whose rule was skipped when the file was parsed is left out without one, and
// stays listed by Skipped. The result can be passed in ScanOptions.Rules to
// restrict one call.
func (r *Rules) Only(ids ...string) (*Rules, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	subset := *r
	subset.list, subset.keywordRules = nil, nil
	for _, rule := range r.list {
		if want[rule.ID] {
			subset.list = append(subset.list, rule)
			delete(want, rule.ID)
		}
	}
	for _, rule := range r.keywordRules {
		if want[rule.ID] {
			subset.keywordRules = append(subset.keywordRules, rule)
			delete(want, rule.ID)
		}
	}
	for _, skipped := range r.skipped {
		delete(want, skipped.ID)
	}
	for id := range want {
		return nil, fmt.Errorf("no rule has the id %s", id)
	}
	subset.index()
	subset.tag = rulesTags.Add(1)
	return &subset, nil
}

// Skipped lists the rules of the parsed file that this version cannot apply:
// one with a validator or an action it does not know, a pattern it cannot
// compile, or a field holding a kind of value it does not read. The other rules
// of the file apply as usual. The file may come from a server newer than this
// binary, so whoever loads one should report what was left out.
func (r *Rules) Skipped() []SkippedRule {
	if r == nil {
		return nil
	}
	return append([]SkippedRule(nil), r.skipped...)
}

// DefaultRules are the rules shipped with the CLI. They are compiled once and,
// like every Rules, never change afterwards.
func DefaultRules() *Rules { return defaultRulesOnce() }

var defaultRulesOnce = sync.OnceValue(func() *Rules {
	rules, err := ParseRules(defaultRules)
	if err != nil {
		panic("censor: the shipped rules do not compile: " + err.Error())
	}
	// Leaving a rule out is for files newer than the binary; the shipped file
	// is exactly as old.
	if len(rules.skipped) > 0 {
		panic("censor: the shipped rule " + rules.skipped[0].ID + " does not compile: " + rules.skipped[0].Reason)
	}
	return rules
})

// ParseRules compiles a YAML (or JSON) rule file. A rule this version cannot
// apply is left out and listed by Skipped rather than failing the file; a file
// with no usable rule, a rule without an id or two rules with one id is an error.
func ParseRules(content []byte) (*Rules, error) {
	var file struct {
		Scoring Scoring     `yaml:"scoring"`
		Rules   []yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, err
	}
	if len(file.Rules) == 0 {
		return nil, errors.New("the rule file has no rules")
	}
	scoring := file.Scoring
	if scoring.KeywordWindow <= 0 {
		scoring.KeywordWindow = 40
	}
	rules := &Rules{scoring: scoring, keywords: newKeywordSet(scoring.Keywords), ignoreValues: map[string]bool{}, tag: rulesTags.Add(1)}
	for _, value := range scoring.IgnoreValues {
		rules.ignoreValues[value] = true
	}
	for _, sub := range scoring.IgnoreSubstrings {
		rules.ignoreSubs = append(rules.ignoreSubs, bytes.ToLower([]byte(sub)))
	}
	for _, pattern := range scoring.IgnorePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("ignore pattern %q: %w", pattern, err)
		}
		rules.ignorePatterns = append(rules.ignorePatterns, re)
	}
	seen := map[string]bool{}
	for i := range file.Rules {
		// Each rule is decoded on its own, so a value of a kind this version
		// does not read costs that rule and not the file.
		rule := &Rule{}
		decodeErr := file.Rules[i].Decode(rule)
		if rule.ID == "" {
			return nil, errors.New("every rule needs an id")
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("rule id %s appears twice", rule.ID)
		}
		seen[rule.ID] = true
		err := decodeErr
		if err == nil {
			err = rule.compile()
		}
		if err == nil && rule.KeywordValue && rules.keywords.empty() {
			err = errors.New("needs a keyword list")
		}
		if err != nil {
			rules.skipped = append(rules.skipped, SkippedRule{ID: rule.ID, Reason: skipReason(err)})
			continue
		}
		if rule.KeywordValue {
			// Keyword rules come after the others wherever two rules tie.
			rule.order = len(file.Rules) + i
			rules.keywordRules = append(rules.keywordRules, rule)
			continue
		}
		rule.order = i
		rules.list = append(rules.list, rule)
	}
	if rules.Len() == 0 {
		first := rules.skipped[0]
		return nil, fmt.Errorf("the rule file has no usable rules: %d skipped, the first %s (%s)", len(rules.skipped), first.ID, first.Reason)
	}
	rules.index()
	return rules, nil
}

// skipReason says in one line why a rule was left out.
func skipReason(err error) string {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) && len(typeErr.Errors) > 0 {
		return "a field holds a value this version does not read: " + shorten(typeErr.Errors[0])
	}
	return shorten(err.Error())
}

func shorten(text string) string {
	const limit = 200
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		return strings.ToValidUTF8(text[:limit], "") + "..."
	}
	return text
}

func intOr(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

// compile readies one rule. Its error is the reason the rule is skipped.
func (rule *Rule) compile() error {
	if rule.Action == "" {
		rule.Action = "redact"
	}
	if rule.Action != "redact" && rule.Action != "alert" {
		return fmt.Errorf("unknown action %q (redact or alert)", rule.Action)
	}
	if rule.Label == "" {
		rule.Label = strings.ReplaceAll(rule.ID, "-", "_")
	}
	// The label goes into the placeholder ph:<label>:<n>.
	if !identifier.MatchString(rule.Label) {
		return errors.New("label must be 1 to 64 of A-Z, a-z, 0-9, '_', '.' and '-'")
	}
	rule.base = intOr(rule.Score, 60)
	rule.redactAt = intOr(rule.RedactAt, 50)
	rule.alertAt = intOr(rule.AlertAt, 30)
	if rule.Action == "alert" {
		rule.redactAt = 1 << 30
	}
	if rule.Validator != "" {
		validate, ok := validators[rule.Validator]
		if !ok {
			return fmt.Errorf("unknown validator %q", rule.Validator)
		}
		rule.validate = validate
	}
	for _, hint := range rule.Hints {
		rule.hints = append(rule.hints, []byte(hint))
	}
	if rule.KeywordValue {
		if rule.MinLength <= 0 {
			rule.MinLength = 16
		}
		if rule.Regex == "" {
			return nil
		}
		// The shape the value after the keyword must have.
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return err
		}
		rule.re = re
		rule.group = max(re.SubexpIndex("secret"), 0)
		return nil
	}
	pattern := rule.Regex
	if pattern == "" {
		if rule.Prefix == "" || rule.Charset == "" {
			return errors.New("needs a regex, a prefix and a charset, or keyword_value")
		}
		if strings.ContainsAny(rule.Charset, "[]") {
			return errors.New("write the charset without brackets")
		}
		low, high := rule.MinLength, rule.MaxLength
		if rule.Length > 0 {
			low, high = rule.Length, rule.Length
		}
		if low <= 0 {
			return errors.New("needs a length or a min_length")
		}
		bound := strconv.Itoa(low) + ","
		if high > 0 {
			bound += strconv.Itoa(high)
		}
		pattern = `\b` + regexp.QuoteMeta(rule.Prefix) + "[" + rule.Charset + "]{" + bound + "}"
		if len(rule.hints) == 0 {
			rule.hints = [][]byte{[]byte(rule.Prefix)}
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	rule.re = re
	rule.group = max(re.SubexpIndex("secret"), 0)
	rule.anchor(pattern)
	return nil
}

// anchor works out whether every match of the pattern begins with one of a few
// literals. If so the rule is tried only where one is found, which gives the
// matches a scan of the whole text would: a match has to begin at one of those
// places, they are tried in order, and each try sees the byte before it and the
// byte after the longest match, which is all a regex can look around at.
func (rule *Rule) anchor(pattern string) {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return
	}
	starts, ok := startLiterals(tree)
	if !ok {
		return
	}
	atStart, err := regexp.Compile(`\A(?:` + pattern + `)`)
	if err != nil {
		return
	}
	afterByte, err := regexp.Compile(`\A[\s\S](?:` + pattern + `)`)
	if err != nil {
		return
	}
	rule.starts, rule.atStart, rule.afterByte, rule.maxLen = starts, atStart, afterByte, maxMatchLength(tree)
}

// matchAt tries an anchored rule at p, where one of its literals begins. It
// returns the range to replace, which is negative when the rule's group took no
// part in the match, and where the whole match ends.
func (rule *Rule) matchAt(data []byte, p int) (start, end, matchEnd int, ok bool) {
	from, re := p, rule.atStart
	if p > 0 {
		from, re = p-1, rule.afterByte
	}
	to := len(data)
	if rule.maxLen > 0 {
		to = min(to, p+rule.maxLen+1)
	}
	m := re.FindSubmatchIndex(data[from:to])
	if m == nil {
		return 0, 0, 0, false
	}
	matchEnd = from + m[1]
	if rule.group == 0 {
		return p, matchEnd, matchEnd, true
	}
	if m[2*rule.group] < 0 {
		return -1, -1, matchEnd, true
	}
	return from + m[2*rule.group], from + m[2*rule.group+1], matchEnd, true
}

// How an anchored rule is applied to one block.
const (
	ruleUntried  = iota
	ruleAnchored // tried where its literals begin
	ruleLeftOut  // it has hints and the block holds none of them
	ruleWhole    // scanned over the whole block, as a rule that is not anchored
)

// eachAnchored applies every anchored rule one of whose literals was found, and
// reports what a scan of the whole text with the rule's regex would. Normally
// the rule is tried at each of those places in order; its matches do not
// overlap, so a place inside the last one is passed over.
//
// A try reads from its place as far as the regex can reach, which for a regex
// with no longest match is the end of the block. Text that begins a thousand
// tokens and ends none would cost a thousand such reads, so the most a rule's
// tries could read is added up first, and a rule that could read more than a
// few times the block is scanned over the whole block instead, once. That
// keeps a scan linear in the text whatever the text is.
func (r *Rules) eachAnchored(data []byte, starts []startHit, found func(rule *Rule, s, e int)) {
	if len(starts) == 0 {
		return
	}
	type progress struct {
		matched, tried int // where the rule last matched to, and was last tried
		reach          int // the most bytes its tries in this block could read
		how            uint8
	}
	done := make([]progress, len(r.list))
	allowance := anchoredAllowance*len(data) + anchoredSlack
	var whole []int32
	for _, at := range starts {
		rule, state := r.list[at.rule], &done[at.rule]
		if state.how == ruleUntried {
			state.how = ruleAnchored
			// Hints mean what they always did: the rule runs only on text
			// that holds one.
			if !rule.mayMatch(data) {
				state.how = ruleLeftOut
			}
		}
		if state.how != ruleAnchored {
			continue
		}
		reach := len(data) - at.pos + 1
		if rule.maxLen > 0 {
			reach = min(reach, rule.maxLen+2)
		}
		if state.reach += reach; state.reach > allowance {
			state.how = ruleWhole
			whole = append(whole, at.rule)
		}
	}
	for _, at := range starts {
		rule, state := r.list[at.rule], &done[at.rule]
		// Two of a rule's literals can begin at one place.
		if state.how != ruleAnchored || at.pos < state.matched || at.pos < state.tried {
			continue
		}
		state.tried = at.pos + 1
		s, e, matchEnd, ok := rule.matchAt(data, at.pos)
		if !ok {
			continue
		}
		state.matched = matchEnd
		if s >= 0 && e > s {
			found(rule, s, e)
		}
	}
	for _, index := range whole {
		r.list[index].eachMatch(data, found)
	}
}

const (
	anchoredAllowance = 4
	anchoredSlack     = 4096
)

// eachMatch runs the rule's regex over the whole text.
func (rule *Rule) eachMatch(data []byte, found func(rule *Rule, s, e int)) {
	for _, m := range rule.re.FindAllSubmatchIndex(data, -1) {
		if s, e := m[2*rule.group], m[2*rule.group+1]; s >= 0 && e > s {
			found(rule, s, e)
		}
	}
}

// shaped narrows the value after a keyword to what the rule's regex takes of
// it. A keyword rule without a regex takes any value whole.
func (rule *Rule) shaped(data []byte, s, e int) (int, int, bool) {
	if rule.re == nil {
		return s, e, true
	}
	m := rule.re.FindSubmatchIndex(data[s:e])
	if m == nil || m[2*rule.group] < 0 || m[2*rule.group+1] <= m[2*rule.group] {
		return 0, 0, false
	}
	return s + m[2*rule.group], s + m[2*rule.group+1], true
}

// Len is the number of rules.
func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.list) + len(r.keywordRules)
}

type ruleSpan struct {
	start, end int
	rule       *Rule
	score      int
}

// score rates one candidate. keyName is the JSON key holding the string, if any.
func (r *Rules) score(rule *Rule, data []byte, start, end int, keys []keywordHit, keyName string, keywordFound bool) int {
	value := data[start:end]
	score := rule.base
	if keywordFound || r.keywordBefore(data, start, keys) || r.keywords.containsFold([]byte(keyName)) {
		score += r.scoring.KeywordBonus
	}
	// A validator only ever adds confidence. A checksum or structure that
	// passes earns the bonus; one that fails changes nothing: the candidate
	// already has its format's prefix, length and alphabet, and it is scored
	// and replaced as a rule without a validator would have it. What is known
	// in public about some of these checksums is second-hand, and formats
	// change, so a failure is never taken as proof that a value is harmless.
	if rule.validate != nil && rule.validate(value) {
		score += r.scoring.ValidatorBonus
	}
	if r.ignored(value, rule.KeywordValue) {
		score -= r.scoring.IgnorePenalty
	}
	return score
}

// keywordBefore reports a keyword ending within the window before start, on the same line.
func (r *Rules) keywordBefore(data []byte, start int, keys []keywordHit) bool {
	from := start - r.scoring.KeywordWindow
	i := sort.Search(len(keys), func(i int) bool { return keys[i].end > from })
	for ; i < len(keys) && keys[i].end <= start; i++ {
		if bytes.IndexByte(data[keys[i].end:start], '\n') < 0 {
			return true
		}
	}
	return false
}

// ignored is a documentation or placeholder value. The ignore patterns describe what
// gets written after a keyword without being a value, so they apply to keyword_value
// candidates only.
func (r *Rules) ignored(value []byte, keywordValue bool) bool {
	if r.ignoreValues[string(value)] {
		return true
	}
	lower := bytes.ToLower(value)
	for _, sub := range r.ignoreSubs {
		if bytes.Contains(lower, sub) {
			return true
		}
	}
	if !keywordValue {
		return false
	}
	for _, re := range r.ignorePatterns {
		if re.Match(value) {
			return true
		}
	}
	return false
}

// rulePass applies the pattern rules to one block. Redacted candidates become
// ph:<label>:<n>; alerted ones are only recorded, with their score. It returns
// the rewritten bytes, the hits, and the found ranges in data's coordinates.
func (ix *Index) rulePass(data []byte, keyName string, rules *Rules) ([]byte, []hit, []rep) {
	if rules == nil {
		return data, nil, nil
	}
	var spans []ruleSpan
	var keys []keywordHit
	var starts []startHit
	keysDone := false
	if rules.literals != nil {
		keys, starts = rules.literals.scan(data)
		keysDone = rules.literals.keywords
	}
	findKeys := func() []keywordHit {
		if !keysDone {
			keys, keysDone = rules.keywords.find(data), true
		}
		return keys
	}
	consider := func(rule *Rule, s, e int, keywordFound bool) {
		if rule.MinEntropy > 0 && entropy(string(data[s:e])) < rule.MinEntropy {
			return
		}
		score := rules.score(rule, data, s, e, findKeys(), keyName, keywordFound)
		if rule.KeywordValue && harmlessShape(data[s:e]) {
			score -= rules.scoring.ShapePenalty
		}
		if score >= rule.alertAt {
			spans = append(spans, ruleSpan{start: s, end: e, rule: rule, score: score})
		}
	}
	candidate := func(rule *Rule, s, e int) { consider(rule, s, e, false) }
	rules.eachAnchored(data, starts, candidate)
	for _, rule := range rules.unanchored {
		if rule.mayMatch(data) {
			rule.eachMatch(data, candidate)
		}
	}
	if len(rules.keywordRules) > 0 {
		// A JSON value whose key is a keyword, such as {"client_secret": "..."}.
		keyHits := rules.keywords.find([]byte(keyName))
		if len(keyHits) > 0 {
			onlyPWD := true
			for _, k := range keyHits {
				onlyPWD = onlyPWD && pathKeyword([]byte(keyName[k.start:k.end]))
			}
			for _, rule := range rules.keywordRules {
				s, e, ok := wholeValue(data, rule.MinLength)
				if !ok || (onlyPWD && looksLikePath(data[s:e])) {
					continue
				}
				if s, e, ok = rule.shaped(data, s, e); ok {
					consider(rule, s, e, true)
				}
			}
		}
		for _, key := range findKeys() {
			// A keyword inside a path or a resource name (arn:...:secret:name) isn't a name.
			if key.start > 0 && (data[key.start-1] == ':' || data[key.start-1] == '/') {
				continue
			}
			s, e, ok := valueAfterKeyword(data, key.end, rules.scoring.KeywordWindow)
			if !ok {
				continue
			}
			// PWD=/home/dev/app in printed environment output is a directory.
			if pathKeyword(data[key.start:key.end]) && looksLikePath(data[s:e]) {
				continue
			}
			if !plausibleSecret(data[s:e]) {
				continue
			}
			for _, rule := range rules.keywordRules {
				if e-s < rule.MinLength {
					continue
				}
				if vs, ve, ok := rule.shaped(data, s, e); ok {
					consider(rule, vs, ve, true)
				}
			}
		}
	}
	if len(spans) == 0 {
		return data, nil, nil
	}
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].score != spans[j].score {
			return spans[i].score > spans[j].score
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].rule.order < spans[j].rule.order
	})
	var hits []hit
	var reps []rep
	var out []byte
	last, covered := 0, 0
	changed := false
	for _, found := range spans {
		if found.start < covered {
			continue
		}
		covered = found.end
		h := hit{kind: kindRule, label: found.rule.Label, rule: found.rule.ID, action: actionAlert, score: found.score, form: "pattern"}
		if found.score >= found.rule.redactAt {
			h.action = actionRedact
			h.placeholder = "ph:" + found.rule.Label + ":" + strconv.Itoa(ix.ruleNumber(found.rule.Label, data[found.start:found.end]))
		}
		hits = append(hits, h)
		reps = append(reps, rep{start: found.start, end: found.end, hit: h})
		if h.action != actionRedact {
			continue
		}
		out = append(out, data[last:found.start]...)
		out = append(out, h.placeholder...)
		last = found.end
		changed = true
	}
	if !changed {
		return data, hits, reps
	}
	out = append(out, data[last:]...)
	return out, hits, reps
}

// ruleNumber numbers each distinct value per label, keeping only a keyed hash of it,
// so the same token gets the same placeholder in every request.
func (ix *Index) ruleNumber(label string, value []byte) int {
	hash := sha256.New()
	hash.Write(ix.key.ruleKey[:])
	hash.Write([]byte(label))
	hash.Write([]byte{0})
	hash.Write(value)
	var key [macSize]byte
	copy(key[:], hash.Sum(nil))
	ix.ruleMu.Lock()
	defer ix.ruleMu.Unlock()
	if n, ok := ix.ruleNums[key]; ok {
		return n
	}
	// The map only grows with distinct matched values; past a bound it starts
	// over rather than grow without limit, at the cost of renumbering.
	if len(ix.ruleNums) >= maxRuleNumbers {
		ix.ruleNums = map[[macSize]byte]int{}
	}
	ix.ruleNext[label]++
	ix.ruleNums[key] = ix.ruleNext[label]
	return ix.ruleNext[label]
}

const maxRuleNumbers = 1 << 16
