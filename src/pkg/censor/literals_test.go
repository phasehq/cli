package censor

import (
	"bytes"
	"math/rand"
	"reflect"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/censortest"
)

func TestStartLiterals(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string // nil when the regex is not anchored; "~" ends a folded literal
	}{
		{`\bgh[pousr]_[A-Za-z0-9]{36}\b`, []string{"gho_", "ghp_", "ghr_", "ghs_", "ghu_"}},
		{`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, []string{"AKIA", "ASIA"}},
		{`\b[sr]k_live_[0-9A-Za-z]{20,}`, []string{"rk_live_", "sk_live_"}},
		{`\bpss_user:v\d+:[0-9a-f]{64}`, []string{"pss_user:v"}},
		{`(?i)aws_secret_access_key["']?\s*[=:]`, []string{"AWS_SECRET_ACCESS_KEY~"}},
		{`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`, []string{"-----BEGIN "}},
		{`\b(?P<secret>AIza[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)`, []string{"AIza"}},
		{`\bdo[por]_v1_[0-9a-f]{64}\b`, []string{"doo_v1_", "dop_v1_", "dor_v1_"}},
		{`\bsk-(?:proj|svcacct|admin)-x`, []string{"sk-admin-x", "sk-proj-x", "sk-svcacct-x"}},
		{`(?i:account|storage)[_.-]?(?i:key)["']?=`, []string{
			"ACCOUNT-KEY~", "ACCOUNT.KEY~", "ACCOUNTKEY~", "ACCOUNT_KEY~", "STORAGE-KEY~", "STORAGE.KEY~", "STORAGEKEY~", "STORAGE_KEY~"}},
		// A choice is followed while the beginning is short, and through a small
		// one a little longer; past that it would only multiply the literals.
		{`[ab][cd]ef`, []string{"acef", "adef", "bcef", "bdef"}},
		{`abcd[xy]z`, []string{"abcdxz", "abcdyz"}},
		{`abcd[0-9]z`, []string{"abcd"}},
		{`abcdefgh[xy]z`, []string{"abcdefgh"}},
		{`\bdapi[0-9a-f]{32}`, []string{"dapi"}},
		{`(?:foo)?bar`, []string{"bar", "foobar"}},
		{`ab(?:cd)+e`, []string{"abcd"}},
		{`ab(?:cd){2,3}e`, []string{"abcd"}},
		{`^abc`, []string{"abc"}},
		{`(?m)^abc$`, []string{"abc"}},
		{`ab|abc|abd`, []string{"ab"}},
		{`ab\x{FFFD}c`, []string{"ab"}},
		{`(?i)1234_`, []string{"1234_"}},
		{`é[^0-9]`, []string{"é"}},
		{`é[0-3]x`, []string{"é0x", "é1x", "é2x", "é3x"}},
		{`a[0-9]+`, []string{"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"}},
		// Nothing fixed to begin with, or too little of it.
		{`[0-9]{8,10}:A[A-Za-z0-9_-]{34}`, nil},
		{`\w+@example\.com`, nil},
		{`a*bc`, nil},
		{`x?y`, nil},
		{`abc|`, nil},
		{`abc|[a-z]+`, nil},
		{`\x{FFFD}abc`, nil},
		{`a[^0-9]+`, nil},
		{`a[0-9a-z]+`, nil},
		{`(?i)k`, nil},
		{`.abc`, nil},
		{`(?:ab)*cd`, nil},
		{`(?:ab){0,2}cd`, nil},
	}
	for _, tc := range cases {
		tree, err := syntax.Parse(tc.pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("%s: %v", tc.pattern, err)
		}
		lits, ok := startLiterals(tree)
		var got []string
		for _, lit := range lits {
			text := lit.text
			if lit.fold {
				text += "~"
			}
			got = append(got, text)
		}
		sort.Strings(got)
		if ok != (tc.want != nil) || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q (%v), want %q", tc.pattern, got, ok, tc.want)
		}
	}
}

func TestMaxMatchLength(t *testing.T) {
	for pattern, want := range map[string]int{
		`\bgh[pousr]_[A-Za-z0-9]{36}\b`: 40,
		`(?:ab|cde)f?`:                  4,
		`a+`:                            0,
		`a{2,}`:                         0,
		`a{2,5}`:                        5,
		`[\s\S]*?x`:                     0,
		`(?i)ab`:                        8, // a folded rune can be a longer one
		`[^x]{2}`:                       8,
		`.{0,3}`:                        12,
		`é[0-9]`:                        3,
		`(?P<secret>ab)(?:[^a-z]|$)`:    6,
	} {
		tree, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("%s: %v", pattern, err)
		}
		if got := maxMatchLength(tree); got != want {
			t.Errorf("%s: %d, want %d", pattern, got, want)
		}
	}
}

// wholeScan is what a rule finds by running its regex over all of the text,
// when the text holds one of its hints: what every rule did before rules were
// anchored.
func wholeScan(rule *Rule, data []byte) [][2]int {
	var found [][2]int
	if !rule.mayMatch(data) {
		return nil
	}
	for _, m := range rule.re.FindAllSubmatchIndex(data, -1) {
		if s, e := m[2*rule.group], m[2*rule.group+1]; s >= 0 && e > s {
			found = append(found, [2]int{s, e})
		}
	}
	return found
}

func anchoredScan(rules *Rules, data []byte) map[string][][2]int {
	found := map[string][][2]int{}
	if rules.literals == nil {
		return found
	}
	_, starts := rules.literals.scan(data)
	rules.eachAnchored(data, starts, func(rule *Rule, s, e int) {
		found[rule.ID] = append(found[rule.ID], [2]int{s, e})
	})
	return found
}

// soup strings pieces together at random, with nothing, a separator or part
// of another piece between them: tokens side by side, cut short, begun twice.
func soup(random *rand.Rand, pieces []string, n int) []byte {
	separators := []string{"", "", " ", "\n", "-", "_", ".", ":", "/", "=", "\"", "x", "9", "é", "\xff", "\u017f", "\u212a"}
	var out []byte
	for i := 0; i < n; i++ {
		piece := pieces[random.Intn(len(pieces))]
		switch random.Intn(6) {
		case 0:
			piece = piece[:random.Intn(len(piece)+1)]
		case 1:
			piece = piece[random.Intn(len(piece)+1):]
		}
		out = append(out, piece...)
		out = append(out, separators[random.Intn(len(separators))]...)
	}
	return out
}

// assertSameAsWholeScan compares the two ways of applying every rule to data,
// and returns how many matches there were to compare.
func assertSameAsWholeScan(t testing.TB, rules *Rules, name string, data []byte) int {
	t.Helper()
	anchored := anchoredScan(rules, data)
	matches := 0
	for _, rule := range rules.list {
		if rule.atStart == nil {
			t.Fatalf("%s is not anchored", rule.ID)
		}
		whole := wholeScan(rule, data)
		if !reflect.DeepEqual(whole, anchored[rule.ID]) {
			t.Fatalf("%s on %s: a whole scan finds %v, the anchored rule %v", rule.ID, name, whole, anchored[rule.ID])
		}
		matches += len(whole)
	}
	return matches
}

// TestAnchoredRulesFindWhatAWholeScanFinds: trying a rule only where one of its
// literals begins must give exactly the matches its regex gives over the whole
// text, on real material and on text built to sit awkwardly.
func TestAnchoredRulesFindWhatAWholeScanFinds(t *testing.T) {
	rules := DefaultRules()
	random := rand.New(rand.NewSource(20261119))
	var pieces []string
	matches, texts := 0, 0
	same := func(name string, data []byte) {
		t.Helper()
		matches += assertSameAsWholeScan(t, rules, name, data)
		texts++
	}
	for _, tc := range formatCases(t) {
		for _, sample := range tc.positives {
			pieces = append(pieces, sample.text, sample.secret)
			same(tc.rule+" positive", []byte(sample.text))
			// At the very start and the very end of the text, and next to a
			// character of more than one byte.
			same(tc.rule+" alone", []byte(sample.secret))
			same(tc.rule+" after é", []byte("é"+sample.secret+"é"))
		}
		for _, text := range tc.nearMisses {
			pieces = append(pieces, text)
			same(tc.rule+" near-miss", []byte(text))
		}
		for _, text := range tc.examples {
			pieces = append(pieces, text)
		}
	}
	for _, rule := range rules.list {
		for _, start := range rule.starts {
			pieces = append(pieces, start.text, strings.ToLower(start.text))
		}
	}
	key := fakePEM(t)
	phase := "pss_service:v2:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + randomString(t, base64URL, 43)
	pieces = append(pieces, key, strings.ReplaceAll(key, "\n", `\n`), key[:len(key)/2], "-----END PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----",
		phase, phase[:90], jwt, "Authorization: Bearer "+jwt, "xoxb-"+randomString(t, decimal, 12)+"-"+randomString(t, alnum, 24),
		"sk_"+"live_"+randomString(t, alnum, 30), "github_pat_"+randomString(t, alnum+"_", 82),
		"aws_secret_access_key = "+randomString(t, base64Std, 40), "AWS_Secret_Access_Key: '"+randomString(t, alnum, 40)+"'",
		"aw\u017f_\u017fecret_acce\u017f\u017f_\u212aey="+randomString(t, alnum, 40), "\u017ftorage_\u212aey="+randomString(t, base64Std, 86)+"==")
	for round := 0; round < 60; round++ {
		same("soup", soup(random, pieces, 120))
	}

	fixture := censortest.NewFixture()
	for name, content := range fixture.Files {
		same(name, []byte(content))
	}
	size := 1 << 20
	if raceEnabled {
		size = 256 << 10
	}
	text := corpus(t, size)
	for i := 0; i < len(text); i += 64 << 10 {
		same("corpus", text[i:min(i+(64<<10), len(text))])
	}
	for name, text := range ordinaryNegatives(t) {
		same(name, []byte(text))
	}
	t.Logf("%d texts, %d matches, the same both ways", texts, matches)
	if matches < 1000 {
		t.Fatalf("only %d matches were compared", matches)
	}
}

// The same property for regexes of shapes the shipped rules do not have:
// assertions other than \b, lazy and nested repeats, alternatives of unequal
// length, case folding beyond ASCII, a group inside trailing context.
func TestAnchoringHoldsForOtherRegexes(t *testing.T) {
	patterns := []string{
		`(?m)^tok_[a-z]{4}$`,
		`\Bgh_[0-9]{3}`,
		`key_(?:[a-z]+?)_end`,
		`ab(?:c|cd)e?`,
		`(?i)straße_[0-9]+`,
		`(?i)sk_[a-z]{3}\b`,
		`xy+z`,
		`é[0-9]{2}`,
		`\bid=(?P<secret>[0-9]{4})(?:[^0-9]|$)`,
		`(?s)BEGIN.*?END`,
		`tok_[a-z]{2,6}$`,
		`ab\x{FFFD}c`,
		`(?:foo)?bar[0-9]`,
		`(?i:account|storage)[_.-]?(?i:key)=[0-9]{2}`,
	}
	var file strings.Builder
	file.WriteString("rules:\n")
	for i, pattern := range patterns {
		file.WriteString("  - id: r" + string(rune('a'+i)) + "\n    regex: '" + pattern + "'\n")
	}
	rules, err := ParseRules([]byte(file.String()))
	if err != nil || len(rules.Skipped()) != 0 || len(rules.unanchored) != 0 {
		t.Fatalf("%v %+v, %d not anchored", err, rules.Skipped(), len(rules.unanchored))
	}
	pieces := []string{
		"tok_abcd", "tok_ab", "tok_abcdefgh", "\ntok_wxyz\n", "gh_123", "xgh_1234", " gh_123", "key_a_end", "key_abc_end_end", "key__end",
		"abc", "abcd", "abcde", "abce", "ab", "straße_12", "STRASSE_1", "STRA\u1e9eE_77", "Straße_", "sk_abc", "SK_abc", "\u017fk_abc", "s\u212a_abc", "sk_abcd",
		"xyz", "xyyyyz", "xz", "é12", "é1", "e12", "id=1234", "id=12345", "id=1234;", "xid=1234", "BEGIN", "END", "BEGIN x END", "BEGINEND",
		"ab\ufffdc", "ab\xffc", "ab\xc3c", "bar1", "foobar2", "foofoobar3", "fobar4", "ACCOUNT_KEY=12", "Storage-Key=34", "\u017ftorage\u212aey=56", "accountkey=7", "account__key=89",
	}
	random := rand.New(rand.NewSource(8959))
	matches := 0
	for _, piece := range pieces {
		matches += assertSameAsWholeScan(t, rules, piece, []byte(piece))
	}
	for round := 0; round < 400; round++ {
		matches += assertSameAsWholeScan(t, rules, "soup", soup(random, pieces, 40))
	}
	t.Logf("%d matches, the same both ways", matches)
	if matches < 1000 {
		t.Fatalf("only %d matches were compared", matches)
	}
}

// keywordReference finds keywords the plain way: every keyword tried at every
// offset, compared without regard to ASCII case.
func keywordReference(words []string, data []byte) []keywordHit {
	var hits []keywordHit
	lower := strings.ToLower(string(asciiOnlyLower(data)))
	for i := range data {
		for _, word := range words {
			word = strings.ToLower(strings.TrimSpace(word))
			if len(word) >= 2 && strings.HasPrefix(lower[i:], word) {
				hits = append(hits, keywordHit{start: i, end: i + len(word)})
			}
		}
	}
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].end < hits[b].end })
	return hits
}

// asciiOnlyLower lowers A-Z and swaps every other byte for itself, so that
// strings.ToLower afterwards changes nothing more.
func asciiOnlyLower(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = lowerTable[b]
		if b >= 0x80 {
			out[i] = 0x01
		}
	}
	return out
}

// TestOnePassFindsTheKeywords: the pass that finds where rules begin also
// finds the keywords, and must report exactly what the keyword set does.
func TestOnePassFindsTheKeywords(t *testing.T) {
	rules := DefaultRules()
	if rules.literals == nil || !rules.literals.keywords {
		t.Fatal("the shipped rules look for keywords in the one pass")
	}
	check := func(name string, data []byte) {
		t.Helper()
		want := rules.keywords.find(data)
		got, _ := rules.literals.scan(data)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the pass found %d keywords, the keyword set %d", name, len(got), len(want))
		}
		// Ties between keywords ending at one place may come in either order.
		reference := keywordReference(rules.scoring.Keywords, data)
		if len(reference) != len(got) {
			t.Fatalf("%s: %d keywords, a plain search finds %d", name, len(got), len(reference))
		}
		for i := range got {
			if got[i].end != reference[i].end {
				t.Fatalf("%s: keyword %d ends at %d, a plain search says %d", name, i, got[i].end, reference[i].end)
			}
		}
	}
	text := corpus(t, 2<<20)
	for i := 0; i < len(text); i += 100 << 10 {
		check("corpus", text[i:min(i+(100<<10), len(text))])
	}
	for name, content := range censortest.NewFixture().Files {
		check(name, []byte(content))
	}
	random := rand.New(rand.NewSource(4086))
	var pieces []string
	for _, word := range rules.scoring.Keywords {
		pieces = append(pieces, word, strings.ToUpper(word), strings.ToUpper(word[:1])+word[1:], word[:len(word)-1], word[1:])
	}
	pieces = append(pieces, "PASSWORD=", "Pwd=", "apiKey", "API-KEY", "é", "\xff", "=", " ", "\n", "x")
	for round := 0; round < 300; round++ {
		check("soup", soup(random, pieces, 60))
	}
	for _, edge := range []string{"", "p", "pw", "pwd", "to", "token", "xtoken", "TOKEN", "password=", "dsn", "ds"} {
		check(edge, []byte(edge))
	}
	// A rule set with no keyword rule leaves keywords to be found when a
	// candidate needs them, and still scores a keyword before a token.
	phaseOnly, err := rules.Only("phase-user-token")
	if err != nil || phaseOnly.literals == nil || phaseOnly.literals.keywords {
		t.Fatalf("a limited set should not look for keywords in the pass: %v", err)
	}
	ix := build(t)
	token := "pss_user:v1:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	out, report := ix.RedactWith([]byte("export PHASE_TOKEN="+token), ScanOptions{Rules: phaseOnly})
	if string(out) != "export PHASE_TOKEN=ph:phase_pat:1" || report.Findings[0].Score != 110 {
		t.Fatalf("%s %+v", out, report.Findings)
	}
}

// TestRuleCostStaysLinear: a rule tried at every place its literal begins must
// not cost a read of the rest of the text each time. Text that begins a
// thousand tokens and ends none is scanned in about the time of any other
// text, gives what a whole scan gives, and the key after it is still found.
func TestRuleCostStaysLinear(t *testing.T) {
	// Before the cost was bounded the worst of these took half a minute.
	limit := 500 * time.Millisecond
	if raceEnabled {
		limit *= 10
	}
	rules := DefaultRules()
	ix := build(t)
	key := fakePEM(t)
	const size = 200 << 10
	for name, unit := range map[string]string{
		"private key headers with no end": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n",
		"certificate headers":             "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkq\n",
		"the starts of JWTs":              "eyJhbGciOiJIUzI1NiJ9-",
		"the starts of Slack tokens":      "xoxb-!",
		"the starts of PyPI tokens":       "pypi-AgEIcHlwaS5vcmc-",
		"the starts of longer GitHub":     "ghs_1_eyJhbGciOiJSUzI1NiJ9-",
		"the starts of OpenAI keys":       "sk-",
		"the starts of Phase tokens":      "pss_service:v1",
		"names of AWS secrets":            "aws_secret_access_key=",
		"names of Azure keys":             "AccountKey=",
	} {
		filler := strings.Repeat(unit, size/len(unit))
		body := []byte("first " + key + filler + "\nlast " + key)
		best := time.Hour
		var out []byte
		for i := 0; i < 3; i++ {
			started := time.Now()
			out, _ = ix.Redact(body)
			best = min(best, time.Since(started))
		}
		t.Logf("%-34s %d KB in %v", name, len(body)>>10, best)
		if best > limit {
			t.Errorf("%s: scanning took %v, over %v", name, best, limit)
		}
		if !bytes.HasPrefix(out, []byte("first ph:private_key:1")) {
			t.Errorf("%s: the key before it was not replaced", name)
		}
		// The key after it is replaced too, unless a header with no end of its
		// own has taken everything up to that key's end, as it always did.
		if name != "private key headers with no end" && !bytes.HasSuffix(out, []byte("\nlast ph:private_key:1\n")) {
			t.Errorf("%s: the key after it was not replaced", name)
		}
		// A shorter stretch of the same is enough to compare with whole scans.
		assertSameAsWholeScan(t, rules, name, []byte(filler[:24<<10]+key))
	}
}

// FuzzAnchoredRules holds the shipped rules to the same property on whatever
// the fuzzer makes of real tokens: the anchored rules find what whole scans find.
func FuzzAnchoredRules(f *testing.F) {
	rules := DefaultRules()
	for _, tc := range formatCases(f) {
		for _, sample := range tc.positives {
			f.Add([]byte(sample.text))
		}
		for _, text := range tc.nearMisses {
			f.Add([]byte(text))
		}
	}
	f.Add([]byte(fakePEM(f) + "-----BEGIN PRIVATE KEY-----\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ aws_secret_access_key=\"\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		assertSameAsWholeScan(t, rules, "fuzz", data)
	})
}

// FuzzParseRules: a rule file comes from outside, so whatever it holds must
// either be refused or give rules that scan without trouble, and a rule that
// is anchored must find what its regex finds over the whole text.
func FuzzParseRules(f *testing.F) {
	f.Add(defaultRules, []byte("token=Zq8Lm2Zr6Tx4Nb9Wc1Ke7 ghp_"+strings.Repeat("a1B2", 9)))
	f.Add([]byte("scoring:\n  keywords: [token]\nrules:\n  - id: a\n    regex: '(?i)k[st]?ab(?:c|cd)e?[0-9]{2,4}$'\n  - id: b\n    keyword_value: true\n    regex: '^[a-f0-9]{8}$'\n    min_length: 8\n  - id: c\n    prefix: zz_\n    charset: a-z\n    length: 4\n  - id: d\n    regex: 'x'\n    validator: later\n"),
		[]byte("Kab12 kSabcd123\nzz_abcd token=0a1b2c3d \u212aab99"))
	f.Add([]byte("rules:\n  - id: a\n    regex: '\\b[sr]k_(?:live|test)_[0-9A-Za-z]{4,}'\n    hints: [k_]\n  - id: b\n    regex: '[0-9]+:[a-z]+'\n"), []byte("sk_live_abcd rk_test_1234 12:ab"))
	f.Fuzz(func(t *testing.T, file, data []byte) {
		if len(file) > 4096 {
			return
		}
		rules, err := ParseRules(file)
		if err != nil {
			return
		}
		if rules.Len() == 0 {
			t.Fatal("a file with no usable rule was accepted")
		}
		for _, s := range rules.Skipped() {
			if s.ID == "" || s.Reason == "" {
				t.Fatalf("skipped %+v", s)
			}
		}
		anchored := anchoredScan(rules, data)
		for _, rule := range rules.list {
			if rule.atStart == nil {
				continue
			}
			if whole := wholeScan(rule, data); !reflect.DeepEqual(whole, anchored[rule.ID]) {
				t.Fatalf("rule %q: a whole scan finds %v, the anchored rule %v", rule.Regex+rule.Prefix, whole, anchored[rule.ID])
			}
		}
		key, _ := NewKey()
		ix, err := NewIndex(key, IndexOptions{Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		ix.Redact(data)
		ix.Find(data)
	})
}
