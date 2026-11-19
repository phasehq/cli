package censor

import (
	"strings"
	"testing"
)

// A rule file can come from a server newer than this binary. A rule it cannot
// apply must cost that rule, be reported, and leave the rest of the file working.
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
  - id: Odd Label
    regex: '\blabel_[a-z0-9]{20}\b'
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
	wantSkipped := map[string]string{
		"later-validator": `unknown validator "luhn-2031"`,
		"later-action":    `unknown action "quarantine"`,
		"later-value":     "does not read",
		"later-list":      "does not read",
		"later-kind":      "needs a regex",
		"later-syntax":    "error parsing regexp",
		"Odd Label":       "label must be",
	}
	skipped := rules.Skipped()
	if len(skipped) != len(wantSkipped) || rules.Len() != 3 {
		t.Fatalf("%d rules, skipped %+v", rules.Len(), skipped)
	}
	for i, s := range skipped {
		if want, ok := wantSkipped[s.ID]; !ok || !strings.Contains(s.Reason, want) || len(s.Reason) > 260 || strings.Contains(s.Reason, "\n") {
			t.Errorf("skipped %+v, want a reason holding %q", s, want)
		}
		// In the order of the file.
		if i > 0 && strings.Index(string(file), "id: "+skipped[i-1].ID) > strings.Index(string(file), "id: "+s.ID) {
			t.Errorf("%s is listed before %s", skipped[i-1].ID, s.ID)
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
	text := "known_" + tail + " later_" + tail + " action_" + tail + " value_" + tail + " list_" + tail + " syntax_" + tail + " label_" + tail + " field_" + tail + " token=Zq8Lm2Zr6Tx4Nb9Wc1Ke7"
	out, report := ix.Redact([]byte(text))
	want := "ph:known:1 later_" + tail + " action_" + tail + " value_" + tail + " list_" + tail + " syntax_" + tail + " label_" + tail + " ph:later_field:1 token=ph:by_keyword:1"
	if string(out) != want || report.Redacted != 3 {
		t.Fatalf("got  %s\nwant %s", out, want)
	}

	// Only passes over a rule the file had and this version skipped, and still
	// refuses an id the file never had.
	limited, err := rules.Only("known", "later-validator")
	if err != nil || limited.Len() != 1 || len(limited.Skipped()) != len(wantSkipped) {
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
}

func TestARuleFileThatCannotBeUsedIsAnError(t *testing.T) {
	for name, file := range map[string]string{
		"not YAML":            "rules: [",
		"no rules":            "scoring:\n  keywords: [token]\n",
		"an empty list":       "rules: []\n",
		"nothing usable":      "rules:\n  - id: a\n    regex: 'x{3}'\n    validator: later\n  - id: b\n    action: later\n    regex: 'y{3}'\n",
		"a rule with no id":   "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - regex: 'def[0-9]{3}'\n",
		"an id that is a map": "rules:\n  - id: {name: a}\n    regex: 'abc[0-9]{3}'\n",
		"a rule not a map":    "rules:\n  - just text\n",
		"an id twice":         "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - id: a\n    regex: 'def[0-9]{3}'\n",
		"a skipped id twice":  "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n  - id: b\n    validator: later\n    regex: 'x'\n  - id: b\n    regex: 'def[0-9]{3}'\n",
		"a bad ignore list":   "scoring:\n  ignore_patterns: ['(']\nrules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n",
		"scoring of a kind":   "scoring:\n  keyword_bonus: plenty\nrules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n",
	} {
		if rules, err := ParseRules([]byte(file)); err == nil {
			t.Errorf("%s: accepted with %d rules", name, rules.Len())
		}
	}
	_, err := ParseRules([]byte("rules:\n  - id: a\n    regex: 'x{3}'\n    validator: later\n  - id: b\n    action: later\n    regex: 'y{3}'\n"))
	if err == nil || !strings.Contains(err.Error(), "no usable rules") || !strings.Contains(err.Error(), "2 skipped") || !strings.Contains(err.Error(), `unknown validator "later"`) {
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
