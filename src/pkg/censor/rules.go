package censor

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

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
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Regex       string `yaml:"regex"`
	Prefix      string `yaml:"prefix"`
	// Charset is the alphabet of a prefix rule's token. With a regex it names
	// the token's own alphabet too. Either way, when more of it follows a match
	// the token ran on past the length the rule allows, and the whole run is
	// taken (see maxTokenRun), so that no tail of it is left behind.
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
	// Keywords are names of the rule's own. When it has any they are used
	// instead of the general keywords for its bonus, which is how a format that
	// is a secret under one name and public under another is told apart.
	// KeywordsExcept are words that cancel the bonus when the same name holds
	// one. A rule with keywords of its own decides alone about a value of its
	// format: a keyword_value rule does not take that value too.
	Keywords       []string `yaml:"keywords"`
	KeywordsExcept []string `yaml:"keywords_except"`

	re       *regexp.Regexp
	group    int
	hints    [][]byte
	base     int
	redactAt int
	alertAt  int
	validate func([]byte) bool
	order    int        // its place in the file, which settles a tie between two rules
	run      *[256]bool // the token's alphabet, for a rule whose match is extended over its run
	own      [][]byte   // its own keywords, in lower case
	except   [][]byte   // the words that cancel them
	note     string     // why Skipped lists the rule although it is applied

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

// SkippedRule is a rule of a parsed file that this version cannot apply as the
// file has it, and why. Nearly always the rule is left out; one whose validator
// alone is unknown is applied without it, and its reason says so. ID is the
// rule's id, or "rule #n" for the n-th rule of the file when its id is not a
// plain identifier, and Reason holds printable text only: both are meant to be
// shown to whoever loaded the file.
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
	leftOut        []string // the ids, as the file has them, of the rules that are not applied
	scoring        Scoring
	keywords       *keywordSet
	ignoreValues   map[string]bool
	ignoreSubs     [][]byte
	ignorePatterns []*regexp.Regexp
	labels         map[string]bool // the labels the file's rules write into placeholders
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
	for _, id := range r.leftOut {
		delete(want, id)
	}
	for id := range want {
		return nil, fmt.Errorf("no rule has the id %s", id)
	}
	subset.index()
	subset.tag = rulesTags.Add(1)
	return &subset, nil
}

// Skipped lists the rules of the parsed file that this version cannot apply as
// the file has them. Left out: a rule with an action or a key it does not know,
// a pattern it cannot compile, a field holding a kind of value it does not
// read, or an id that is not a plain identifier. Applied, without its
// validator: a rule naming a validator it does not know, since a validator only
// ever adds confidence. The other rules of the file apply as usual. The file
// may come from a server newer than this binary, so whoever loads one should
// report what is listed here.
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

// Bounds on a rule file, and the scoring numbers it takes when it leaves one
// out: those of the shipped file. A file without them would otherwise score a
// keyword at nothing, and the keyword rule would never fire.
const (
	maxRules       = 512 // a file with more is refused
	minIgnoreEntry = 4   // a shorter ignore entry would match nearly everything
	minOwnKeyword  = 3

	defaultKeywordWindow  = 40
	defaultKeywordBonus   = 30
	defaultValidatorBonus = 20
	defaultIgnorePenalty  = 100
	defaultShapePenalty   = 25
)

// ruleID is what a rule's id has to be. Ids are printed, compared and sent on,
// so they keep to one plain form.
var ruleID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ruleKeys are the keys a rule may have: the yaml names of Rule's fields.
var ruleKeys = func() map[string]bool {
	keys := map[string]bool{}
	fields := reflect.TypeOf(Rule{})
	for i := 0; i < fields.NumField(); i++ {
		if name := fields.Field(i).Tag.Get("yaml"); name != "" {
			keys[name] = true
		}
	}
	return keys
}()

// scoringFile is the scoring section as a file writes it, where a number can
// be left out.
type scoringFile struct {
	Keywords         []string `yaml:"keywords"`
	KeywordWindow    *int     `yaml:"keyword_window"`
	KeywordBonus     *int     `yaml:"keyword_bonus"`
	ValidatorBonus   *int     `yaml:"validator_bonus"`
	IgnorePenalty    *int     `yaml:"ignore_penalty"`
	ShapePenalty     *int     `yaml:"shape_penalty"`
	IgnoreValues     []string `yaml:"ignore_values"`
	IgnoreSubstrings []string `yaml:"ignore_substrings"`
	IgnorePatterns   []string `yaml:"ignore_patterns"`
}

func (f scoringFile) scoring() Scoring {
	scoring := Scoring{
		Keywords:         f.Keywords,
		KeywordWindow:    intOr(f.KeywordWindow, defaultKeywordWindow),
		KeywordBonus:     intOr(f.KeywordBonus, defaultKeywordBonus),
		ValidatorBonus:   intOr(f.ValidatorBonus, defaultValidatorBonus),
		IgnorePenalty:    intOr(f.IgnorePenalty, defaultIgnorePenalty),
		ShapePenalty:     intOr(f.ShapePenalty, defaultShapePenalty),
		IgnoreValues:     f.IgnoreValues,
		IgnoreSubstrings: f.IgnoreSubstrings,
		IgnorePatterns:   f.IgnorePatterns,
	}
	if scoring.KeywordWindow <= 0 {
		scoring.KeywordWindow = defaultKeywordWindow
	}
	return scoring
}

// ParseRules compiles a YAML (or JSON) rule file. A rule this version cannot
// apply is left out and listed by Skipped rather than failing the file. What
// would quietly switch protection off is an error instead: a file with no
// usable rule or more than 512 rules, a rule without an id, two rules with one
// id, and an ignore entry so short, or an ignore pattern so wide, that it
// matches nearly every value.
func ParseRules(content []byte) (*Rules, error) {
	var file struct {
		Scoring scoringFile `yaml:"scoring"`
		Rules   []yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, err
	}
	if len(file.Rules) == 0 {
		return nil, errors.New("the rule file has no rules")
	}
	if len(file.Rules) > maxRules {
		return nil, fmt.Errorf("the rule file has %d rules, more than %d", len(file.Rules), maxRules)
	}
	scoring := file.Scoring.scoring()
	// An ignore entry that is empty, or a character or two, is in every value:
	// it would drop every candidate, and nothing would say so.
	for _, list := range []struct {
		name    string
		entries []string
	}{{"ignore_values", scoring.IgnoreValues}, {"ignore_substrings", scoring.IgnoreSubstrings}, {"ignore_patterns", scoring.IgnorePatterns}} {
		for _, entry := range list.entries {
			if len(entry) < minIgnoreEntry {
				return nil, fmt.Errorf("%s holds the entry %q: one under %d bytes would match nearly every value", list.name, entry, minIgnoreEntry)
			}
		}
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
			return nil, fmt.Errorf("ignore pattern %q: %w", truncate(pattern), err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("ignore pattern %q matches the empty string, and so every value", truncate(pattern))
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
			return nil, fmt.Errorf("rule id %q appears twice", truncate(rule.ID))
		}
		seen[rule.ID] = true
		// What Skipped lists gets printed by whoever loaded the file, so an id
		// that is not a plain identifier is never handed on: the rule is left
		// out and listed by its place in the file.
		listed, err := rule.ID, decodeErr
		if !ruleID.MatchString(rule.ID) {
			listed = "rule #" + strconv.Itoa(i+1)
			err = errors.New("its id is not 1 to 64 of a-z, 0-9 and '-', beginning with a letter or digit")
		}
		if err == nil {
			// A key this version does not know may be a constraint, as a
			// misspelt min_entropy is: applying the rule without it could
			// replace what the rule was written to leave alone.
			if key, unknown := unknownKey(&file.Rules[i]); unknown {
				err = fmt.Errorf("unknown key %q", truncate(key))
			}
		}
		if err == nil {
			err = rule.compile()
		}
		if err == nil && rule.KeywordValue && rules.keywords.empty() {
			err = errors.New("needs a keyword list")
		}
		if err != nil {
			rules.skipped = append(rules.skipped, SkippedRule{ID: listed, Reason: skipReason(err)})
			rules.leftOut = append(rules.leftOut, rule.ID)
			continue
		}
		if rule.note != "" {
			rules.skipped = append(rules.skipped, SkippedRule{ID: listed, Reason: shorten(rule.note)})
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
	// Of the whole file, and shared by every subset of it: a call limited to
	// some rules still knows the placeholders the others wrote.
	rules.labels = map[string]bool{}
	for _, rule := range append(append([]*Rule(nil), rules.list...), rules.keywordRules...) {
		rules.labels[rule.Label] = true
	}
	if rules.Len() == 0 {
		first := rules.skipped[0]
		return nil, fmt.Errorf("the rule file has no usable rules: %d skipped, the first %s (%s)", len(rules.skipped), first.ID, first.Reason)
	}
	rules.index()
	return rules, nil
}

// unknownKey returns a key of the rule that is not one of ruleKeys.
func unknownKey(node *yaml.Node) (string, bool) {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	if node.Kind != yaml.MappingNode {
		return "", false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		// A merge key brings in the members of another mapping.
		if key.Tag == "!!merge" {
			continue
		}
		if !ruleKeys[key.Value] {
			return key.Value, true
		}
	}
	return "", false
}

// skipReason says in one line why a rule was left out.
func skipReason(err error) string {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) && len(typeErr.Errors) > 0 {
		return "a field holds a value this version does not read: " + shorten(typeErr.Errors[0])
	}
	return shorten(err.Error())
}

// shorten makes text from a rule file fit to show: one line, of printable
// characters only, and not long.
func shorten(text string) string {
	const limit = 200
	text = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case r == utf8.RuneError || !unicode.IsPrint(r):
			return -1
		}
		return r
	}, text)
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
			// A validator only ever adds confidence, so the rule is worth
			// applying without one this version does not know. Leaving it out
			// would let a file that renames a validator switch the rule off.
			rule.note = fmt.Sprintf("unknown validator %q: the rule is applied without it", rule.Validator)
		}
		rule.validate = validate
	}
	for _, hint := range rule.Hints {
		rule.hints = append(rule.hints, []byte(hint))
	}
	var err error
	if rule.own, err = ownWords("keywords", rule.Keywords); err != nil {
		return err
	}
	// A word too short to mean anything would cancel the bonus under every name.
	if rule.except, err = ownWords("keywords_except", rule.KeywordsExcept); err != nil {
		return err
	}
	if len(rule.except) > 0 && len(rule.own) == 0 {
		return errors.New("keywords_except needs keywords")
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
	if rule.Charset != "" {
		if strings.ContainsAny(rule.Charset, "[]") {
			return errors.New("write the charset without brackets")
		}
		class, err := regexp.Compile("^[" + rule.Charset + "]$")
		if err != nil {
			return err
		}
		rule.run = new([256]bool)
		for b := 0; b < utf8.RuneSelf; b++ {
			rule.run[b] = class.Match([]byte{byte(b)})
		}
	}
	pattern := rule.Regex
	if pattern == "" {
		if rule.Prefix == "" || rule.Charset == "" {
			return errors.New("needs a regex, a prefix and a charset, or keyword_value")
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
	// A run is followed only from a match that began with a literal: without
	// one, where the rule's token begins is anyone's guess.
	if rule.atStart == nil {
		rule.run = nil
	}
	return nil
}

// ownWords readies a rule's own keywords, or the words that cancel them.
func ownWords(name string, words []string) ([][]byte, error) {
	var out [][]byte
	for _, word := range words {
		word = strings.ToLower(strings.TrimSpace(word))
		if len(word) < minOwnKeyword {
			return nil, fmt.Errorf("%s holds the entry %q, under %d bytes", name, truncate(word), minOwnKeyword)
		}
		out = append(out, []byte(word))
	}
	return out, nil
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

func (s ruleSpan) replaces() bool { return s.score >= s.rule.redactAt }

// maxTokenRun is the longest a token can run on in its own alphabet past what
// its rule matched and still be taken, whole. Something longer is not a token.
const maxTokenRun = 512

// score rates one candidate. matched is where the rule's own match ended, which
// is what a validator checks; the candidate may run on to end. keyName is the
// JSON key holding the string, if any.
func (r *Rules) score(rule *Rule, data []byte, start, matched, end int, keys []keywordHit, held []placed, keyName string, keywordFound bool) int {
	score := rule.base
	switch {
	case len(rule.own) > 0:
		// Its own names decide, whatever the general keywords say.
		if rule.named(data, start, r.scoring.KeywordWindow, held, keyName) {
			score += r.scoring.KeywordBonus
		}
	case keywordFound || r.keywordBefore(data, start, keys, held) || r.keywords.containsFold([]byte(keyName)):
		score += r.scoring.KeywordBonus
	}
	// A validator only ever adds confidence. A checksum or structure that
	// passes earns the bonus; one that fails changes nothing: the candidate
	// already has its format's prefix, length and alphabet, and it is scored
	// and replaced as a rule without a validator would have it. What is known
	// in public about some of these checksums is second-hand, and formats
	// change, so a failure is never taken as proof that a value is harmless.
	if rule.validate != nil && rule.validate(data[start:matched]) {
		score += r.scoring.ValidatorBonus
	}
	if r.ignored(data[start:end], rule.KeywordValue) {
		score -= r.scoring.IgnorePenalty
	}
	return score
}

// keywordBefore reports a keyword ending within the window before start, on the
// same line, with no placeholder of a rule between the two. Such a placeholder
// stands where a longer value stood when a rule replaced it, in an earlier pass
// over this text: the keyword was further from the candidate then, and counting
// it now would have a second pass replace what the first only reported.
func (r *Rules) keywordBefore(data []byte, start int, keys []keywordHit, held []placed) bool {
	from := start - r.scoring.KeywordWindow
	i := sort.Search(len(keys), func(i int) bool { return keys[i].end > from })
	for ; i < len(keys) && keys[i].end <= start; i++ {
		if bytes.IndexByte(data[keys[i].end:start], '\n') < 0 && !ruleWroteIn(held, keys[i].end, start) {
			return true
		}
	}
	return false
}

// named reports whether one of the rule's own keywords names the candidate at
// start: it ends within the window before it on the same line, or sits in the
// JSON key holding it. A name that also holds one of the rule's exceptions
// does not count, so that NEXT_PUBLIC_GOOGLE_API_KEY is not GOOGLE_API_KEY. Nor
// does a name with a rule's placeholder between it and the candidate, as for
// the general keywords.
func (rule *Rule) named(data []byte, start, window int, held []placed, keyName string) bool {
	if key := []byte(keyName); holdsFold(key, rule.own) && !holdsFold(key, rule.except) {
		return true
	}
	line := start
	for line > 0 && start-line < window+maxOwnName && data[line-1] != '\n' {
		line--
	}
	for _, word := range rule.own {
		for at := line; at+len(word) <= start; at++ {
			if at+len(word) <= start-window || !equalLower(data[at:at+len(word)], word) {
				continue
			}
			// The name the keyword sits in, as far as it runs either way.
			from, to := at, at+len(word)
			for from > 0 && at-from < maxOwnName && isIdentByte(data[from-1]) {
				from--
			}
			for to < len(data) && to-at < maxOwnName && isIdentByte(data[to]) {
				to++
			}
			if !holdsFold(data[from:to], rule.except) && !ruleWroteIn(held, to, start) {
				return true
			}
		}
	}
	return false
}

// maxOwnName bounds how far a name is followed around one of a rule's own keywords.
const maxOwnName = 64

// holdsFold reports whether text holds one of the lower-case words, whatever
// the case of its ASCII letters.
func holdsFold(text []byte, words [][]byte) bool {
	for _, word := range words {
		for at := 0; at+len(word) <= len(text); at++ {
			if equalLower(text[at:at+len(word)], word) {
				return true
			}
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
	// A token of three parts reads like a dotted name to the patterns, and is
	// not one.
	if !keywordValue || dottedToken(value) {
		return false
	}
	for _, re := range r.ignorePatterns {
		if re.Match(value) {
			return true
		}
	}
	return false
}

var placeholderPrefix = []byte("ph:")

// placed is a placeholder found in the text: what this matcher wrote into it,
// here or in an earlier pass over it.
type placed struct {
	start, end int
	rule       bool // ph:<label>:<n>, written by a rule
}

// placeholders finds the placeholders in the text, in order: ph:<label>:<n>
// for a rule and ph:<type>:<id> for an indexed value, each part 1 to 64
// identifier characters. label says whether a first part is one of the labels
// the rules write, and typed whether it is the type of an indexed value.
//
// After a rule's label come digits and nothing else, so a rule's placeholder
// ends with them even when more text follows it at once. Any other is read as
// far as identifier characters go. "graph:node:1" ends the same way and is not
// one, so where a letter, digit or '_' comes before ph: the first part has to
// be a label or a type this matcher writes. That is a placeholder written
// right after a word, as in /botph:telegram_bot_token:1/ and -pph:secret:db.
func placeholders(data []byte, label, typed func(part []byte) bool) []placed {
	return placeholdersAfter(data, label, typed, nil)
}

// placeholdersAfter is placeholders for bytes the inventory has just written
// into. bare are the placeholders with no id it wrote, in order: each ends
// where it was written, so a colon and a token right after one are text like
// any other.
func placeholdersAfter(data []byte, label, typed func(part []byte) bool, bare [][2]int) []placed {
	var found []placed
	for from := 0; ; {
		at := bytes.Index(data[from:], placeholderPrefix)
		if at < 0 {
			return found
		}
		at += from
		from = at + len(placeholderPrefix)
		for len(bare) > 0 && bare[0][0] < at {
			bare = bare[1:]
		}
		if len(bare) > 0 && bare[0][0] == at {
			found = append(found, placed{start: at, end: bare[0][1]})
			from = bare[0][1]
			continue
		}
		colon := identifierRun(data, from)
		if colon == from || colon >= len(data) || data[colon] != ':' {
			// ph:<type> alone stands for a value whose id is withheld.
			if colon > from && typed(data[from:colon]) {
				found = append(found, placed{start: at, end: colon})
				from = colon
			}
			continue
		}
		part, end := data[from:colon], colon+1
		isType := typed(part)
		if !isType && label(part) {
			for end < len(data) && end-colon <= 10 && data[end] >= '0' && data[end] <= '9' {
				end++
			}
			if end > colon+1 {
				found = append(found, placed{start: at, end: end, rule: true})
				from = end
			}
			continue
		}
		end = identifierRun(data, end)
		if end == colon+1 || (at > 0 && isWordByte(data[at-1]) && !isType) {
			continue
		}
		found = append(found, placed{start: at, end: end})
		from = end
	}
}

// identifierRun is where the identifier characters beginning at from end, 64 of
// them at most: what a placeholder's label, type or id is made of.
func identifierRun(data []byte, from int) int {
	end := from
	for end < len(data) && end-from < 64 && (isWordByte(data[end]) || data[end] == '.' || data[end] == '-') {
		end++
	}
	return end
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (lowerTable[b] >= 'a' && lowerTable[b] <= 'z')
}

// within reports whether pos lies in one of the placeholders.
func within(held []placed, pos int) bool {
	i := sort.Search(len(held), func(i int) bool { return held[i].end > pos })
	return i < len(held) && held[i].start <= pos
}

// splits reports whether pos falls inside a placeholder, past its first byte:
// a range that ends there holds part of it.
func splits(held []placed, pos int) bool {
	i := sort.Search(len(held), func(i int) bool { return held[i].end > pos })
	return i < len(held) && held[i].start < pos
}

// beginsIn reports whether a placeholder begins at or after from and before to.
func beginsIn(held []placed, from, to int) bool {
	i := sort.Search(len(held), func(i int) bool { return held[i].start >= from })
	return i < len(held) && held[i].start < to
}

// ruleWroteIn reports whether a placeholder that a rule wrote begins at or
// after from and before to.
func ruleWroteIn(held []placed, from, to int) bool {
	for i := sort.Search(len(held), func(i int) bool { return held[i].start >= from }); i < len(held) && held[i].start < to; i++ {
		if held[i].rule {
			return true
		}
	}
	return false
}

// apart is data[from:to] without the placeholders in it, and whether one of
// them was written by a rule.
func apart(data []byte, from, to int, held []placed) (rest []byte, byRule bool) {
	for i := sort.Search(len(held), func(i int) bool { return held[i].end > from }); i < len(held) && held[i].start < to; i++ {
		rest = append(rest, data[from:max(held[i].start, from)]...)
		from = min(held[i].end, to)
		byRule = byRule || held[i].rule
	}
	return append(rest, data[from:to]...), byRule
}

// outside drops the keywords that sit inside a placeholder. A placeholder is
// opaque: ph:secret:db_password names a value that is gone, and what follows
// it in the text is not that password.
func outside(keys []keywordHit, held []placed) []keywordHit {
	if len(held) == 0 {
		return keys
	}
	kept := keys[:0]
	for _, key := range keys {
		if !within(held, key.start) {
			kept = append(kept, key)
		}
	}
	return kept
}

// unescaped returns the bytes the rules read when an escape sits just before a
// place one of them can begin: a copy of data in which the last character of
// such an escape is the character the escape stands for. It returns nil when
// there is none, which is nearly always.
//
// A token after a literal \n, as in a log line carried inside a JSON string, or
// after %3D in a URL, follows a letter or a digit, so the word boundary its
// rule begins with does not hold there. Reading the escape as what it stands
// for gives the rule the text it would have had unescaped: white space or '='
// before the token, and a boundary. An escape that stands for a letter, a digit
// or '_' stays one, so no rule begins to match inside a word because of this.
// Nothing moves: every range a rule finds is a range of data too.
func unescaped(data []byte, starts []startHit) []byte {
	var view []byte
	for _, at := range starts {
		b, ok := escapeBefore(data, at.pos)
		if !ok || b == data[at.pos-1] {
			continue
		}
		if view == nil {
			view = append([]byte(nil), data...)
		}
		view[at.pos-1] = b
	}
	return view
}

// escapeBefore is the character that an escape ending just before pos stands
// for: a newline, tab or carriage return for \n, \t and \r, and its byte for
// %XX. The other two-character escapes of JSON (\", \/ and \\) end in the
// character they stand for already.
func escapeBefore(data []byte, pos int) (byte, bool) {
	if pos >= 2 && data[pos-2] == '\\' {
		switch data[pos-1] {
		case 'n':
			return '\n', true
		case 't':
			return '\t', true
		case 'r':
			return '\r', true
		}
	}
	if pos >= 3 && data[pos-3] == '%' && classHex[data[pos-2]] && classHex[data[pos-1]] {
		return unhex(data[pos-2])<<4 | unhex(data[pos-1]), true
	}
	return 0, false
}

func unhex(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	}
	return b - 'A' + 10
}

// rulePass applies the pattern rules to one block. Redacted candidates become
// ph:<label>:<n>; alerted ones are only recorded, with their score. It returns
// the rewritten bytes, the hits, and the found ranges in data's coordinates.
func (ix *Index) rulePass(data []byte, keyName string, rules *Rules) ([]byte, []hit, []rep) {
	return ix.rulePassAfter(data, keyName, rules, nil)
}

// rulePassAfter is rulePass over bytes the inventory has rewritten, where
// bare says which placeholders it wrote with no id (see placeholders).
func (ix *Index) rulePassAfter(data []byte, keyName string, rules *Rules, bare [][2]int) ([]byte, []hit, []rep) {
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
	// What this matcher already wrote into the text is not looked at again: no
	// candidate begins there, and a keyword there is no keyword. That is what
	// leaves text that was rewritten once the same when it is scanned again.
	held := placeholdersAfter(data, func(part []byte) bool { return rules.labels[string(part)] }, func(part []byte) bool {
		_, typed := ix.types[string(part)]
		return typed
	}, bare)
	keys = outside(keys, held)
	findKeys := func() []keywordHit {
		if !keysDone {
			keys, keysDone = outside(rules.keywords.find(data), held), true
		}
		return keys
	}
	// The regexes read view; everything else, and what is replaced, is data.
	view := data
	if decoded := unescaped(data, starts); decoded != nil {
		view = decoded
		_, starts = rules.literals.scan(view)
	}
	consider := func(rule *Rule, s, e int, keywordFound bool) {
		matched := e
		if rule.run != nil {
			// The token ran on past what its rule allows: all of it, or none.
			for e < len(data) && e-s <= maxTokenRun && rule.run[data[e]] {
				e++
			}
			if e > matched && e-s > maxTokenRun {
				return
			}
		}
		// A placeholder is opaque. A candidate may hold one whole, as a key
		// block holds the lines an indexed key was replaced by; it never begins
		// at one or inside one, and never ends inside one, which is how the
		// letters a placeholder begins with would complete a token before it.
		if within(held, s) || splits(held, e) || bytes.HasPrefix(data[s:e], placeholderPrefix) {
			return
		}
		if rule.MinEntropy > 0 && entropy(string(data[s:e])) < rule.MinEntropy {
			return
		}
		// A value after a keyword that holds a placeholder is a candidate for
		// what else it holds: the placeholder's own label must not make one of
		// it. And when a rule wrote that placeholder, an earlier pass saw this
		// value and did not take it, or it would have taken all of it as one.
		// Without this a second pass would replace what the first left.
		if rule.KeywordValue && beginsIn(held, s, e) {
			rest, byRule := apart(data, s, e, held)
			if byRule || len(rest) < rule.MinLength || !plausibleSecret(rest) || entropy(string(rest)) < rule.MinEntropy {
				return
			}
		}
		score := rules.score(rule, data, s, matched, e, findKeys(), held, keyName, keywordFound)
		if rule.KeywordValue && harmlessShape(data[s:e]) {
			score -= rules.scoring.ShapePenalty
		}
		if score >= rule.alertAt {
			spans = append(spans, ruleSpan{start: s, end: e, rule: rule, score: score})
		}
	}
	candidate := func(rule *Rule, s, e int) { consider(rule, s, e, false) }
	rules.eachAnchored(view, starts, candidate)
	for _, rule := range rules.unanchored {
		if rule.mayMatch(view) {
			rule.eachMatch(view, candidate)
		}
	}
	if len(rules.keywordRules) > 0 {
		// A JSON value whose key is a keyword, such as {"client_secret": "..."}.
		name := []byte(keyName)
		if keyHits := rules.keywords.find(name); len(keyHits) > 0 {
			onlyPWD, other := true, namesNoSecret(name, keyHits, 0)
			for _, k := range keyHits {
				onlyPWD = onlyPWD && pathKeyword(name[k.start:k.end])
			}
			for _, rule := range rules.keywordRules {
				s, e, ok := wholeValue(data, rule.MinLength)
				if !ok || (onlyPWD && looksLikePath(data[s:e])) || (other && urlPassword(string(data[s:e])) == "") {
					continue
				}
				// A word, a name or a path with no digit in it is no value here
				// either: {"token": "/var/run/secrets/token"}.
				if !plausibleSecret(data[s:e]) {
					continue
				}
				if s, e, ok = rule.shaped(data, s, e); ok {
					consider(rule, s, e, true)
				}
			}
		} else if len(name) > 0 {
			// A rule with names of its own is tried under those too: AccountKey
			// holds none of the general keywords.
			for _, rule := range rules.keywordRules {
				if !holdsFold(name, rule.own) || holdsFold(name, rule.except) {
					continue
				}
				if s, e, ok := wholeValue(data, rule.MinLength); ok {
					if s, e, ok = rule.shaped(data, s, e); ok {
						consider(rule, s, e, true)
					}
				}
			}
		}
		for i, key := range findKeys() {
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
			// secretName, token_file and tokenizer name things that are not the
			// secret, and registry/path/name:tag is an image and its tag. A URL
			// with a password in it is a credential whatever it is called.
			if imageTag(data, key.start, nameEnd(data, key.end), s, e) || (namesNoSecret(data, keys, i) && urlPassword(string(data[s:e])) == "") {
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
	var hits []hit
	var reps []rep
	var out []byte
	last := 0
	changed := false
	for _, found := range settle(data, spans) {
		h := hit{kind: kindRule, label: found.rule.Label, rule: found.rule.ID, action: actionAlert, score: found.score, form: "pattern"}
		if found.replaces() {
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

// settle decides what the candidates of one block come to, and returns it in
// the order of the text with nothing overlapping.
//
// Candidates that will be replaced and overlap are replaced as one, over their
// union and under the label of the one that scored highest. Taking only the
// best of them would leave the rest of a longer value behind: an access key id
// and the secret written after it, a token and what a second rule saw of the
// same value. A candidate that only alerts never widens a replacement and is
// not reported where one covers it; of alerts that overlap each other the
// first, and the best of those beginning at one place, is kept.
func settle(data []byte, spans []ruleSpan) []ruleSpan {
	spans = withoutShadowed(data, spans)
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
	var replaced []ruleSpan
	for _, s := range spans {
		if !s.replaces() {
			continue
		}
		if n := len(replaced); n > 0 && s.start < replaced[n-1].end {
			group := &replaced[n-1]
			if s.score > group.score {
				group.rule, group.score = s.rule, s.score
			}
			group.end = max(group.end, s.end)
			continue
		}
		replaced = append(replaced, s)
	}
	var settled []ruleSpan
	next, covered := 0, 0
	for _, s := range spans {
		if s.replaces() {
			continue
		}
		// The replacements that end before this alert begins are behind it.
		for ; next < len(replaced) && replaced[next].end <= s.start; next++ {
			settled = append(settled, replaced[next])
		}
		if (next < len(replaced) && replaced[next].start < s.end) || s.start < covered {
			continue
		}
		covered = s.end
		settled = append(settled, s)
	}
	settled = append(settled, replaced[next:]...)
	sort.SliceStable(settled, func(i, j int) bool { return settled[i].start < settled[j].start })
	return settled
}

// withoutShadowed drops the keyword_value candidates for a value that a rule
// with keywords of its own has matched. Such a rule knows the value's format
// and which names make it a secret; when it only reports a Google API key under
// apiKey in a Firebase config, the general keyword rule must not replace the
// key after all. What the keyword candidate holds beyond the rule's match has
// to be punctuation only: a value that goes on is something else.
func withoutShadowed(data []byte, spans []ruleSpan) []ruleSpan {
	var deciding []ruleSpan
	for _, s := range spans {
		if len(s.rule.own) > 0 && !s.rule.KeywordValue {
			deciding = append(deciding, s)
		}
	}
	if len(deciding) == 0 {
		return spans
	}
	sort.SliceStable(deciding, func(i, j int) bool { return deciding[i].start < deciding[j].start })
	// The furthest any of them reaches, among those beginning at or before each.
	reach := make([]int, len(deciding))
	for i, s := range deciding {
		reach[i] = s.end
		if i > 0 {
			reach[i] = max(reach[i], reach[i-1])
		}
	}
	kept := spans[:0]
	for _, s := range spans {
		if s.rule.KeywordValue && len(s.rule.own) == 0 {
			i := sort.Search(len(deciding), func(i int) bool { return deciding[i].start > s.start }) - 1
			if i >= 0 && reach[i] > s.start && !holdsAlphanumeric(data[min(reach[i], s.end):s.end]) {
				continue
			}
		}
		kept = append(kept, s)
	}
	return kept
}

func holdsAlphanumeric(text []byte) bool {
	for _, b := range text {
		if b != '_' && isWordByte(b) {
			return true
		}
	}
	return false
}

// ruleNumber numbers each distinct value per label, keeping only a keyed hash of it,
// so the same token gets the same placeholder in every request.
func (ix *Index) ruleNumber(label string, value []byte) int {
	hash := sha256.New()
	hash.Write(ix.ruleKey[:])
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
