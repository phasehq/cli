package censor

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
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
// the value written right after a secret-sounding keyword.
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
	// Hints are literal strings at least one of which every match contains. The
	// regex only runs on text holding one, which is what keeps rules cheap.
	Hints []string `yaml:"hints"`

	re       *regexp.Regexp
	group    int
	hints    [][]byte
	base     int
	redactAt int
	alertAt  int
	validate func([]byte) bool
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

// Rules is a compiled rule file.
type Rules struct {
	list           []*Rule
	keywordRules   []*Rule
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

// Only returns the rules whose ids are given, sharing everything else. An id
// that is not in the set is an error, so a typo never silently drops a rule.
// The result can be passed in ScanOptions.Rules to restrict one call.
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
	for id := range want {
		return nil, fmt.Errorf("no rule has the id %s", id)
	}
	subset.tag = rulesTags.Add(1)
	return &subset, nil
}

// DefaultRules are the rules shipped with the CLI. They are compiled once and,
// like every Rules, never change afterwards.
func DefaultRules() *Rules { return defaultRulesOnce() }

var defaultRulesOnce = sync.OnceValue(func() *Rules {
	rules, err := ParseRules(defaultRules)
	if err != nil {
		panic("censor: the shipped rules do not compile: " + err.Error())
	}
	return rules
})

// ParseRules compiles a YAML (or JSON) rule file.
func ParseRules(content []byte) (*Rules, error) {
	var file struct {
		Scoring Scoring `yaml:"scoring"`
		Rules   []*Rule `yaml:"rules"`
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
	for _, rule := range file.Rules {
		if err := rule.compile(); err != nil {
			return nil, err
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("rule id %s appears twice", rule.ID)
		}
		seen[rule.ID] = true
		if rule.KeywordValue {
			if rules.keywords.empty() {
				return nil, fmt.Errorf("rule %s needs a keyword list", rule.ID)
			}
			rules.keywordRules = append(rules.keywordRules, rule)
			continue
		}
		rules.list = append(rules.list, rule)
	}
	return rules, nil
}

func intOr(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func (rule *Rule) compile() error {
	if rule.ID == "" {
		return errors.New("every rule needs an id")
	}
	if rule.Action == "" {
		rule.Action = "redact"
	}
	if rule.Action != "redact" && rule.Action != "alert" {
		return fmt.Errorf("rule %s: action must be redact or alert", rule.ID)
	}
	if rule.Label == "" {
		rule.Label = strings.ReplaceAll(rule.ID, "-", "_")
	}
	// The label goes into the placeholder ph:<label>:<n>.
	if !identifier.MatchString(rule.Label) {
		return fmt.Errorf("rule %s: label must be 1 to 64 of A-Z, a-z, 0-9, '_', '.' and '-'", rule.ID)
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
			return fmt.Errorf("rule %s: unknown validator %q", rule.ID, rule.Validator)
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
		return nil
	}
	pattern := rule.Regex
	if pattern == "" {
		if rule.Prefix == "" || rule.Charset == "" {
			return fmt.Errorf("rule %s: needs a regex, a prefix and a charset, or keyword_value", rule.ID)
		}
		if strings.ContainsAny(rule.Charset, "[]") {
			return fmt.Errorf("rule %s: write the charset without brackets", rule.ID)
		}
		low, high := rule.MinLength, rule.MaxLength
		if rule.Length > 0 {
			low, high = rule.Length, rule.Length
		}
		if low <= 0 {
			return fmt.Errorf("rule %s: needs a length or a min_length", rule.ID)
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
		return fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	rule.re = re
	rule.group = max(re.SubexpIndex("secret"), 0)
	return nil
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
	keysDone := false
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
	for _, rule := range rules.list {
		if !rule.mayMatch(data) {
			continue
		}
		for _, m := range rule.re.FindAllSubmatchIndex(data, -1) {
			s, e := m[2*rule.group], m[2*rule.group+1]
			if s >= 0 && e > s {
				consider(rule, s, e, false)
			}
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
				if s, e, ok := wholeValue(data, rule.MinLength); ok && !(onlyPWD && looksLikePath(data[s:e])) {
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
			for _, rule := range rules.keywordRules {
				if e-s >= rule.MinLength && plausibleSecret(data[s:e]) {
					consider(rule, s, e, true)
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
		return spans[i].end > spans[j].end
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
