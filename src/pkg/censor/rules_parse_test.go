package censor

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A rule file can come from a server newer than this binary. A rule it cannot
// apply must cost that rule, be reported, and leave the rest of the file working.
// One whose validator alone is unknown is applied without it, and reported too.
func TestARuleFileSurvivesARuleItDoesNotUnderstand(t *testing.T) {
	file := []byte(`
scoring:
  keywords: [token]
  keyword_bonus: 30
rules:
  - id: known
    regex: '\bknown_[a-z0-9]{20}\b'
  - id: later-validator
    regex: '\blater_[a-z0-9]{20}\b'
    validator: luhn-2031
  - id: later-action
    regex: '\baction_[a-z0-9]{20}\b'
    action: quarantine
  - id: later-value
    regex: '\bvalue_[a-z0-9]{20}\b'
    score: {base: 60, ceiling: 90}
  - id: later-list
    regex: ['\blist_[a-z0-9]{20}\b', '\bother_[a-z0-9]{20}\b']
  - id: later-kind
    wordlist: [alpha, beta]
  - id: later-syntax
    regex: '\bsyntax_(?=[a-z])[a-z0-9]{20}'
  - id: Odd Id
    regex: '\boddid_[a-z0-9]{20}\b'
  - id: odd-label
    regex: '\blabel_[a-z0-9]{20}\b'
    label: Odd Label
  - id: later-field
    regex: '\bfield_[a-z0-9]{20}\b'
    severity: high
  - id: by-keyword
    keyword_value: true
`)
	rules, err := ParseRules(file)
	if err != nil {
		t.Fatal(err)
	}
	// In the order of the file. The rule with an id that is no identifier is
	// listed by its place, the eighth.
	wantSkipped := []SkippedRule{
		{ID: "later-validator", Reason: `unknown validator "luhn-2031": the rule is applied without it`},
		{ID: "later-action", Reason: `unknown action "quarantine"`},
		{ID: "later-value", Reason: "does not read"},
		{ID: "later-list", Reason: "does not read"},
		{ID: "later-kind", Reason: `unknown key "wordlist"`},
		{ID: "later-syntax", Reason: "error parsing regexp"},
		{ID: "rule #8", Reason: "its id is not"},
		{ID: "odd-label", Reason: "label must be"},
		{ID: "later-field", Reason: `unknown key "severity"`},
	}
	skipped := rules.Skipped()
	if len(skipped) != len(wantSkipped) || rules.Len() != 3 {
		t.Fatalf("%d rules, skipped %+v", rules.Len(), skipped)
	}
	for i, s := range skipped {
		if want := wantSkipped[i]; s.ID != want.ID || !strings.Contains(s.Reason, want.Reason) || len(s.Reason) > 260 || strings.Contains(s.Reason, "\n") {
			t.Errorf("skipped %+v, want %s with a reason holding %q", s, want.ID, want.Reason)
		}
	}
	// What Skipped returns is the caller's own.
	skipped[0].ID = "changed"
	if rules.Skipped()[0].ID == "changed" {
		t.Fatal("Skipped handed out its own list")
	}

	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	tail := "a1b2c3d4e5f6g7h8i9j0"
	text := "known_" + tail + " later_" + tail + " action_" + tail + " value_" + tail + " list_" + tail + " syntax_" + tail + " oddid_" + tail + " label_" + tail + " field_" + tail + " token=Zq8Lm2Zr6Tx4Nb9Wc1Ke7"
	out, report := ix.Redact([]byte(text))
	// The rule with the unknown validator is applied; the one with the unknown
	// key, which may have been a constraint, is not.
	want := "ph:known:1 ph:later_validator:1 action_" + tail + " value_" + tail + " list_" + tail + " syntax_" + tail + " oddid_" + tail + " label_" + tail + " field_" + tail + " token=ph:by_keyword:1"
	if string(out) != want || report.Redacted != 3 {
		t.Fatalf("got  %s\nwant %s", out, want)
	}

	// Only takes a rule that is applied though listed, passes over one the file
	// had and this version left out, whatever its id, and still refuses an id
	// the file never had.
	limited, err := rules.Only("known", "later-validator", "later-action", "Odd Id")
	if err != nil || limited.Len() != 2 || len(limited.Skipped()) != len(wantSkipped) {
		t.Fatalf("%v %d", err, limited.Len())
	}
	if none, err := rules.Only("later-action"); err != nil || none.Len() != 0 {
		t.Fatalf("a set of only skipped rules: %v", err)
	} else if out, _ := ix.RedactWith([]byte(text), ScanOptions{Rules: none}); string(out) != text {
		t.Fatalf("an empty set found something: %s", out)
	}
	if _, err := rules.Only("known", "never-there"); err == nil {
		t.Fatal("an id the file never had was accepted")
	}
	if _, err := rules.Only("rule #8"); err == nil {
		t.Fatal("the name a rule is listed by was taken for an id")
	}
}

func TestARuleFileThatCannotBeUsedIsAnError(t *testing.T) {
	for name, file := range map[string]string{
		"not YAML":            "rules: [",
		"no rules":            "scoring:\n  keywords: [token]\n",
		"an empty list":       "rules: []\n",
		"nothing usable":      "rules:\n  - id: a\n    regex: 'x{3}'\n    action: later\n  - id: b\n    regex: 'y{3}('\n",
		"a rule with no id":   "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - regex: 'def[0-9]{3}'\n",
		"an id that is a map": "rules:\n  - id: {name: a}\n    regex: 'abc[0-9]{3}'\n",
		"a rule not a map":    "rules:\n  - just text\n",
		"an id twice":         "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - id: a\n    regex: 'def[0-9]{3}'\n",
		"a skipped id twice":  "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - id: b\n    action: later\n    regex: 'x'\n  - id: b\n    regex: 'def[0-9]{3}'\n",
		"a bad ignore list":   "scoring:\n  ignore_patterns: ['abcd(']\nrules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n",
		"scoring of a kind":   "scoring:\n  keyword_bonus: plenty\nrules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n",
	} {
		if rules, err := ParseRules([]byte(file)); err == nil {
			t.Errorf("%s: accepted with %d rules", name, rules.Len())
		}
	}
	_, err := ParseRules([]byte("rules:\n  - id: a\n    regex: 'x{3}'\n    action: later\n  - id: b\n    regex: 'y{3}('\n"))
	if err == nil || !strings.Contains(err.Error(), "no usable rules") || !strings.Contains(err.Error(), "2 skipped") || !strings.Contains(err.Error(), `unknown action "later"`) {
		t.Fatalf("%v", err)
	}
	// A keyword rule in a file without keywords cannot do anything.
	rules, err := ParseRules([]byte("rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - id: k\n    keyword_value: true\n"))
	if err != nil || rules.Len() != 1 || len(rules.Skipped()) != 1 || rules.Skipped()[0].ID != "k" {
		t.Fatalf("%v %+v", err, rules.Skipped())
	}
	// The names validators had before still load.
	rules, err = ParseRules([]byte("rules:\n  - id: a\n    regex: '\\bgh[pousr]_[A-Za-z0-9]{36}\\b'\n    validator: github-checksum\n  - id: b\n    regex: '\\bAKIA[0-9A-Z]{16}\\b'\n    validator: aws-key-id\n"))
	if err != nil || rules.Len() != 2 || len(rules.Skipped()) != 0 {
		t.Fatalf("%v %+v", err, rules.Skipped())
	}
}

// A regex that does not begin with a literal still works as it did: over the
// whole text, and only on text that holds one of its hints.
func TestHintedRulesStillScanTheWholeText(t *testing.T) {
	rules, err := ParseRules([]byte(`
rules:
  - id: digits-then-colon
    regex: '\b[0-9]{6}:[a-f0-9]{12}\b'
    hints: [':']
  - id: no-hints
    regex: '[A-Z]{3}-[0-9]{9}-[A-Z]{3}'
  - id: one-byte-prefix
    prefix: Q
    charset: A-Za-z0-9
    length: 12
`))
	if err != nil || len(rules.unanchored) != 3 || rules.literals != nil {
		t.Fatalf("%v: %d rules scan the whole text", err, len(rules.unanchored))
	}
	ix, err := NewIndex(newKey(t), IndexOptions{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := ix.Redact([]byte("a 123456:0a1b2c3d4e5f b ABC-123456789-XYZ c Q1a2B3c4D5e6F d"))
	if string(out) != "a ph:digits_then_colon:1 b ph:no_hints:1 c ph:one_byte_prefix:1 d" {
		t.Fatalf("%s", out)
	}
	// Beside rules that are anchored, and with a keyword rule, in one set.
	mixed, err := ParseRules([]byte(`
scoring:
  keywords: [token]
  keyword_bonus: 30
rules:
  - id: anchored
    regex: '\bzz_[0-9]{6}\b'
  - id: digits-then-colon
    regex: '\b[0-9]{6}:[a-f0-9]{12}\b'
    hints: [':']
  - id: by-keyword
    keyword_value: true
`))
	if err != nil || len(mixed.unanchored) != 1 || mixed.literals == nil {
		t.Fatalf("%v", err)
	}
	out, _ = ix.RedactWith([]byte("zz_123456 123456:0a1b2c3d4e5f token=Zq8Lm2Zr6Tx4Nb9Wc1Ke7 zz_12345"), ScanOptions{Rules: mixed})
	if string(out) != "ph:anchored:1 ph:digits_then_colon:1 token=ph:by_keyword:1 zz_12345" {
		t.Fatalf("%s", out)
	}
}

// A rule file must not be able to switch protection off without an error or a
// report: each of these is the shipped file with one thing wrong.
func TestARuleFileCannotQuietlySwitchProtectionOff(t *testing.T) {
	shipped := string(defaultRules)
	change := func(old, new string) []byte {
		t.Helper()
		if strings.Count(shipped, old) != 1 {
			t.Fatalf("the shipped file holds %q %d times", old, strings.Count(shipped, old))
		}
		return []byte(strings.Replace(shipped, old, new, 1))
	}
	classic, hugging := checksummed(t, "ghp_"), fresh(t, func() string { return "hf" + "_" + randomString(t, asciiLetters, 34) })
	password := opaque(t, 24)
	text := "clone with " + classic + "\npassword=" + password + "\nlogin with " + hugging + "\n"
	scan := func(rules *Rules) string {
		t.Helper()
		ix, err := NewIndex(newKey(t), IndexOptions{Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := ix.Redact([]byte(text))
		return string(out)
	}
	if out := scan(DefaultRules()); out != "clone with ph:github_token:1\npassword=ph:keyword_secret:1\nlogin with ph:huggingface_token:1\n" {
		t.Fatalf("the shipped file: %s", out)
	}

	// An ignore entry that is in every value used to drop every candidate.
	for name, file := range map[string][]byte{
		"an empty ignore substring":       change("    - changeme\n", "    - changeme\n    - ''\n"),
		"an ignore substring of a letter": change("    - changeme\n", "    - changeme\n    - e\n"),
		"one of three bytes":              change("    - changeme\n", "    - changeme\n    - abc\n"),
		"an empty ignore value":           change("    - ASIAIOSFODNN7EXAMPLE\n", "    - ASIAIOSFODNN7EXAMPLE\n    - ''\n"),
		"an empty ignore pattern":         change("  ignore_patterns:\n", "  ignore_patterns:\n    - ''\n"),
		"an ignore pattern for anything":  change("  ignore_patterns:\n", "  ignore_patterns:\n    - '(?s).*'\n"),
		"one that may match nothing":      change("  ignore_patterns:\n", "  ignore_patterns:\n    - '^(?:example)?$'\n"),
	} {
		if rules, err := ParseRules(file); err == nil {
			t.Errorf("%s: accepted, and the text became %q", name, scan(rules))
		} else if !strings.Contains(err.Error(), "ignore") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseRules(change("    - changeme\n", "    - changeme\n    - abcd\n")); err != nil {
		t.Errorf("an ignore substring of four bytes: %v", err)
	}
	// A stray dash is no entry at all.
	if rules, err := ParseRules(change("    - changeme\n", "    - changeme\n    -\n")); err != nil || scan(rules) != scan(DefaultRules()) {
		t.Errorf("a stray dash in the list: %v", err)
	}

	// A file without the scoring numbers used to score a keyword at nothing, so
	// the keyword rule never fired. They are the shipped file's now.
	numbers := regexp.MustCompile(`(?m)^  (keyword_window|keyword_bonus|validator_bonus|ignore_penalty|shape_penalty): \d+\n`)
	if len(numbers.FindAllString(shipped, -1)) != 5 {
		t.Fatal("the shipped file does not set its five scoring numbers")
	}
	bare, err := ParseRules([]byte(numbers.ReplaceAllString(shipped, "")))
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultRules().scoring
	if got := bare.scoring; got.KeywordWindow != want.KeywordWindow || got.KeywordBonus != want.KeywordBonus || got.ValidatorBonus != want.ValidatorBonus ||
		got.IgnorePenalty != want.IgnorePenalty || got.ShapePenalty != want.ShapePenalty {
		t.Fatalf("a file with no numbers scores with %+v", got)
	}
	if want.KeywordWindow != defaultKeywordWindow || want.KeywordBonus != defaultKeywordBonus || want.ValidatorBonus != defaultValidatorBonus ||
		want.IgnorePenalty != defaultIgnorePenalty || want.ShapePenalty != defaultShapePenalty {
		t.Fatalf("the defaults are not the shipped file's numbers: %+v", want)
	}
	if out := scan(bare); out != scan(DefaultRules()) {
		t.Fatalf("a file with no numbers: %s", out)
	}
	// A number the file does give is the file's, nought included.
	zero, err := ParseRules(change("  keyword_bonus: 30\n", "  keyword_bonus: 0\n"))
	if err != nil || zero.scoring.KeywordBonus != 0 || strings.Contains(scan(zero), "ph:keyword_secret") {
		t.Fatalf("keyword_bonus: 0 was not kept: %v", err)
	}

	// A validator this version does not know: the rule is applied without it,
	// since a validator only ever adds, and listed.
	renamed, err := ParseRules(change("validator: github_crc32", "validator: github_crc32_v2"))
	if err != nil {
		t.Fatal(err)
	}
	skipped := renamed.Skipped()
	if len(skipped) != 1 || skipped[0].ID != "github-classic-token" || skipped[0].Reason != `unknown validator "github_crc32_v2": the rule is applied without it` || renamed.Len() != DefaultRules().Len() {
		t.Fatalf("a renamed validator: %d rules, %+v", renamed.Len(), skipped)
	}
	if out := scan(renamed); out != scan(DefaultRules()) {
		t.Fatalf("a renamed validator switched the rule off: %s", out)
	}
	ix, _ := NewIndex(newKey(t), IndexOptions{Rules: renamed})
	if _, report := ix.Redact([]byte("clone with " + classic)); len(report.Findings) != 1 || report.Findings[0].Score != 60 {
		t.Fatalf("without its validator the rule scores as one that has none: %+v", report.Findings)
	}

	// A key this version does not know may be a constraint: the rule is left
	// out, and listed. It used to be applied without the constraint.
	typo, err := ParseRules(change("    regex: '\\bhf_[A-Za-z]{34}\\b'\n    min_entropy: 3.0", "    regex: '\\bhf_[A-Za-z]{34}\\b'\n    min_entorpy: 3.0"))
	if err != nil {
		t.Fatal(err)
	}
	skipped = typo.Skipped()
	if len(skipped) != 1 || skipped[0].ID != "huggingface-token" || skipped[0].Reason != `unknown key "min_entorpy"` || typo.Len() != DefaultRules().Len()-1 {
		t.Fatalf("a misspelt key: %d rules, %+v", typo.Len(), skipped)
	}
	if out := scan(typo); !strings.Contains(out, hugging) || strings.Contains(out, classic) {
		t.Fatalf("a misspelt key: %s", out)
	}

	// An id is a plain identifier, or the rule is left out and listed by its
	// place: nothing a file calls a rule reaches whoever prints the list.
	hostile, err := ParseRules([]byte("rules:\n  - id: \"x\\e[31mRED\\n\\tinjected line\"\n    regex: 'abc[0-9]{3}'\n  - id: UPPER\n    regex: 'ghi[0-9]{3}'\n    validator: \"\\e[2Jnope\\u202e\"\n" +
		"  - id: " + strings.Repeat("a", 65) + "\n    regex: 'jkl[0-9]{3}'\n  - id: -dash\n    regex: 'mno[0-9]{3}'\n  - id: ok\n    regex: 'def[0-9]{3}'\n    validator: \"\\e[2Jnope\\u202e\\0\"\n  - id: ok-2\n    regex: 'pqr[0-9]{3}'\n    score: \"\\e[1mbold\"\n"))
	if err != nil || hostile.Len() != 1 {
		t.Fatalf("%v", err)
	}
	skipped = hostile.Skipped()
	if len(skipped) != 6 || skipped[0].ID != "rule #1" || skipped[1].ID != "rule #2" || skipped[2].ID != "rule #3" || skipped[3].ID != "rule #4" || skipped[4].ID != "ok" || skipped[5].ID != "ok-2" {
		t.Fatalf("%+v", skipped)
	}
	printable := regexp.MustCompile(`^[ -~]+$`)
	for _, s := range skipped {
		if !printable.MatchString(s.ID) || !printable.MatchString(s.Reason) {
			t.Errorf("a listed rule holds what does not print: %q %q", s.ID, s.Reason)
		}
	}
	if !strings.Contains(skipped[4].Reason, `nope`) || !strings.Contains(skipped[4].Reason, "applied without it") {
		t.Errorf("%+v", skipped[4])
	}
	if _, err := ParseRules([]byte("rules:\n  - id: \"a\\e[31m\"\n    regex: 'abc'\n  - id: \"a\\e[31m\"\n    regex: 'def'\n")); err == nil || !printable.MatchString(err.Error()) {
		t.Errorf("an id twice: %q", err)
	}
	for _, id := range []string{"a", "0", "a-b", "a1", "1a", strings.Repeat("a", 64), "github-classic-token"} {
		if rules, err := ParseRules([]byte("rules:\n  - id: " + id + "\n    regex: 'abc[0-9]{3}'\n")); err != nil || len(rules.Skipped()) != 0 {
			t.Errorf("the id %s was refused: %v", id, err)
		}
	}
	for _, id := range []string{"A", "a_b", "a.b", "a b", "-a", "é", strings.Repeat("a", 65)} {
		if rules, err := ParseRules([]byte("rules:\n  - id: ok\n    regex: 'def[0-9]{3}'\n  - id: \"" + id + "\"\n    regex: 'abc[0-9]{3}'\n")); err != nil || len(rules.Skipped()) != 1 || rules.Skipped()[0].ID != "rule #2" {
			t.Errorf("the id %q was taken: %v", id, err)
		}
	}
}

// ruleFileOf writes a file of n rules, each with a pattern of its own.
func ruleFileOf(n int, pattern func(i int) string) []byte {
	var file strings.Builder
	file.WriteString("rules:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&file, "  - id: r%d\n    regex: '%s'\n", i, pattern(i))
	}
	return []byte(file.String())
}

// What a file can make a scan cost is bounded: 512 rules, and 64 beginnings a
// rule in the table every position of the text is looked up in.
func TestARuleFileIsBounded(t *testing.T) {
	distinct := func(i int) string { return fmt.Sprintf(`tok%d_[0-9]{4}`, i) }
	if rules, err := ParseRules(ruleFileOf(maxRules, distinct)); err != nil || rules.Len() != maxRules {
		t.Fatalf("%d rules: %v", maxRules, err)
	}
	if _, err := ParseRules(ruleFileOf(maxRules+1, distinct)); err == nil || !strings.Contains(err.Error(), "more than 512") {
		t.Fatalf("%d rules: %v", maxRules+1, err)
	}

	// A rule that can begin in more ways than the table takes is still applied,
	// from fewer and shorter beginnings or over the whole text.
	random := rand.New(rand.NewSource(512))
	var words []string
	for len(words) < 300 {
		words = append(words, fmt.Sprintf("%c%c%c%c", 'a'+random.Intn(26), 'a'+random.Intn(26), 'a'+random.Intn(26), 'a'+random.Intn(26)))
	}
	rules, err := ParseRules([]byte("rules:\n  - id: wide\n    regex: '\\b(?:" + strings.Join(words, "|") + ")_[0-9]{6}\\b'\n  - id: other\n    regex: '\\bzz_[0-9]{6}\\b'\n"))
	if err != nil || rules.Len() != 2 {
		t.Fatalf("%v", err)
	}
	for _, rule := range rules.list {
		if len(rule.starts) > maxStartLiterals {
			t.Errorf("%s has %d beginnings in the table", rule.ID, len(rule.starts))
		}
	}
	ix, err := NewIndex(newKey(t), IndexOptions{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := ix.Redact([]byte("a " + words[0] + "_123456 b " + words[299] + "_654321 c zz_111111")); string(out) != "a ph:wide:1 b ph:wide:2 c ph:other:1" {
		t.Fatalf("%s", out)
	}

	// The worst a file can do: every rule beginning the same way, and text that
	// begins all of them at every other byte.
	limit := 2 * time.Second
	if raceEnabled {
		limit *= 10
	}
	shared, err := ParseRules(ruleFileOf(maxRules, func(i int) string { return fmt.Sprintf(`ab[c-d]%dz`, i) }))
	if err != nil || len(shared.unanchored) != 0 {
		t.Fatalf("%v", err)
	}
	ix, err = NewIndex(newKey(t), IndexOptions{Rules: shared})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("abc", (100<<10)/3) + " abc7z")
	started := time.Now()
	out, _ := ix.Redact(body)
	elapsed := time.Since(started)
	t.Logf("%d rules with one beginning over %d KB: %v", maxRules, len(body)>>10, elapsed)
	if !strings.HasSuffix(string(out), " ph:r7:1") {
		t.Fatalf("the rule in the crowd was not applied")
	}
	if elapsed > limit {
		t.Fatalf("scanning took %v, over %v", elapsed, limit)
	}
}

// TestDamagedRuleFilesAreRefusedOrUsable: a rule file comes from outside. The
// shipped one, damaged in every way a file gets damaged and with odd values
// swapped in, is either refused or gives rules that scan, and neither takes
// long: ParseRules never panics on what it is given.
func TestDamagedRuleFilesAreRefusedOrUsable(t *testing.T) {
	rounds := 600
	if raceEnabled || testing.Short() {
		rounds = 120
	}
	lines := strings.Split(string(defaultRules), "\n")
	random := rand.New(rand.NewSource(20261119))
	odd := []string{"", "~", "null", "[]", "{}", "[a, b]", "{a: 1}", "-1", "0", "99999999999999999999", "1e99", ".nan", ".inf", "true", "!!binary aGVsbG8=", "'('", "'[a-'",
		`'\b(?P<secret>)x'`, `'x*'`, `'(?i)k'`, `'\x{FFFD}ab'`, `'(?:a|b|)cd'`, `'[\x{10000}-\x{10FFFF}]ab'`, `'\x{D7FF}\x{E000}'`, `'(?s).{0,1000}'`, `'a{1000}b{1000}c{1000}'`,
		"&a x", "*a", "'K\u017f'", `'\pL{3}'`, `'(?U)ab+?'`, `"\xff\xfe"`, "'  '", "[public, '']", "<<: *a", "? [a, b]\n      : c", "'\x1b[31m'", "[[[[[[[[", "a: b: c"}
	sample := []byte("export GITHUB_TOKEN=" + checksummed(t, "ghp_") + " password=" + opaque(t, 24) + " AccountKey=" + randomString(t, base64Std, 86) + "==; " +
		"K\u017f\xff x*x secret-token:" + opaque(t, 30) + "\n-----BEGIN PRIVATE KEY-----\nabc\nph:secret:a %3Dhvs." + randomString(t, alnum, 130) + "\n")
	parsed, refused := 0, 0
	slowest := time.Duration(0)
	for round := 0; round < rounds; round++ {
		mutated := append([]string(nil), lines...)
		for n := 1 + random.Intn(4); n > 0; n-- {
			i := random.Intn(len(mutated))
			switch random.Intn(8) {
			case 0: // drop a line
				mutated = append(mutated[:i], mutated[i+1:]...)
			case 1: // repeat a line somewhere else
				j := random.Intn(len(mutated))
				mutated = append(mutated[:j], append([]string{mutated[i]}, mutated[j:]...)...)
			case 2: // an odd value for a field
				if colon := strings.Index(mutated[i], ": "); colon > 0 {
					mutated[i] = mutated[i][:colon+2] + odd[random.Intn(len(odd))]
				}
			case 3: // change the indent
				mutated[i] = strings.Repeat(" ", random.Intn(7)) + strings.TrimLeft(mutated[i], " ")
			case 4: // cut the line short
				mutated[i] = mutated[i][:random.Intn(len(mutated[i])+1)]
			case 5: // flip a bit
				if len(mutated[i]) > 0 {
					b := []byte(mutated[i])
					b[random.Intn(len(b))] ^= byte(1 << random.Intn(8))
					mutated[i] = string(b)
				}
			case 6: // cut the file short
				if random.Intn(6) == 0 {
					mutated = mutated[:i]
				}
			case 7: // an odd item in a list
				if strings.HasPrefix(strings.TrimLeft(mutated[i], " "), "- ") {
					mutated[i] = mutated[i][:strings.Index(mutated[i], "- ")+2] + odd[random.Intn(len(odd))]
				}
			}
			if len(mutated) == 0 {
				mutated = []string{"rules:"}
			}
		}
		started := time.Now()
		rules, err := ParseRules([]byte(strings.Join(mutated, "\n")))
		slowest = max(slowest, time.Since(started))
		if err != nil {
			refused++
			continue
		}
		parsed++
		if rules.Len() == 0 {
			t.Fatal("a file with no usable rule was accepted")
		}
		for _, s := range rules.Skipped() {
			if s.ID == "" || s.Reason == "" || strings.ContainsAny(s.ID+s.Reason, "\x1b\n\r\t\x00") {
				t.Fatalf("a listed rule: %q %q", s.ID, s.Reason)
			}
		}
		ix, err := NewIndex(newKey(t), IndexOptions{Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := ix.Redact(sample)
		if again, _ := ix.Redact(out); string(again) != string(out) {
			t.Fatalf("a second pass changed the text under a damaged file:\n%s\n%s", out, again)
		}
		ix.Find(sample)
	}
	t.Logf("%d files parsed and scanned, %d refused, the slowest to parse %v", parsed, refused, slowest)
	if parsed < rounds/5 || refused < rounds/20 {
		t.Fatalf("the damage is not of both kinds: %d parsed, %d refused", parsed, refused)
	}
	limit := 500 * time.Millisecond
	if raceEnabled {
		limit *= 10
	}
	if slowest > limit {
		t.Fatalf("a file took %v to parse", slowest)
	}

	// Parsing costs in proportion to the file: twice the rules, about twice
	// the time, with patterns as large as the regexp package lets one be.
	costly := func(n int) time.Duration {
		file := ruleFileOf(n, func(i int) string { return fmt.Sprintf(`zz%d(?:[a-z]{1000}[0-9]{1000}){0,1}[a-f]{1000}`, i) })
		best := time.Hour
		for i := 0; i < 3; i++ {
			started := time.Now()
			if rules, err := ParseRules(file); err != nil || rules.Len() != n {
				t.Fatalf("%v", err)
			}
			best = min(best, time.Since(started))
		}
		return best
	}
	small, large := costly(32), costly(128)
	t.Logf("32 large rules parse in %v, 128 in %v", small, large)
	if large > 8*small+50*time.Millisecond {
		t.Fatalf("four times the rules took %v, against %v", large, small)
	}
}
