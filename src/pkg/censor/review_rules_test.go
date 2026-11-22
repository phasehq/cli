package censor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/censortest"
)

// What a review of the pattern rules found, one test a finding. Every value
// here is made at run time, from pieces, so no file holds anything shaped like
// a live credential.

// opaque is a random value with no format that the keyword rule is sure to
// take after a keyword. Random letters and digits are not always that: about
// one such value of 24 in fifty is all letters and then a digit, which reads
// as an identifier; one in a few hundred spells a keyword such as pwd or dsn,
// which makes a name of the text after it; and a short one can repeat its
// characters until it is too plain. A test of where a value sits must not fail
// once in fifty runs over what the value happens to be.
func opaque(t testing.TB, n int) string {
	t.Helper()
	rules := DefaultRules()
	for {
		value := randomString(t, asciiLetters, 1) + randomString(t, alnum, n-2) + randomString(t, "23456789", 1)
		if text := []byte(value); !rules.ignored(text, true) && len(rules.keywords.find(text)) == 0 && entropy(value) >= 4 && !harmlessShape(text) {
			return value
		}
	}
}

func awsKeyIDText(t testing.TB) string {
	return fresh(t, func() string { return "AKIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) })
}

func telegramToken(t testing.TB) string {
	return fresh(t, func() string {
		return randomString(t, "123456789", 1) + randomString(t, decimal, 9) + ":AA" + randomString(t, base64URL, 33)
	})
}

// scanned is what scanning plain text gives: the text that came out and the
// rule findings.
func scanned(t testing.TB, ix *Index, text string) (string, []Finding) {
	t.Helper()
	out, report := ix.Redact([]byte(text))
	if report.Inventory != 0 {
		t.Fatalf("an inventory hit in %q", text)
	}
	return string(out), report.Findings
}

// Where two rules see parts of one value, all of it goes, under the label of
// the rule that scored highest. Taking only the best match left the rest of
// the value in the request.
func TestOverlappingMatchesAreReplacedAsOne(t *testing.T) {
	ix := build(t)
	keyID, rest := awsKeyIDText(t), opaque(t, 40)
	classic, bot := checksummed(t, "ghp_"), telegramToken(t)
	sid := fresh(t, func() string { return "SK" + randomString(t, lowerHex, 32) })
	for _, tc := range []struct {
		name, text, want, rule string
		score                  int
	}{
		{"an access key id and the secret after it", "S3_CREDENTIALS=" + keyID + ":" + rest, "S3_CREDENTIALS=ph:aws_access_key_id:1", "aws-access-key-id", 110},
		{"a token and what follows a slash", "DEPLOY_KEY_SECRET=" + classic + "/" + rest, "DEPLOY_KEY_SECRET=ph:github_token:1", "github-classic-token", 110},
		{"a bot token and more", "BOT_TOKEN=" + bot + ":" + rest, "BOT_TOKEN=ph:keyword_secret:1", "keyword-high-entropy", 50},
		{"a key SID and its secret", "TWILIO_AUTH=" + sid + ":" + rest, "TWILIO_AUTH=ph:keyword_secret:1", "keyword-high-entropy", 50},
		{"quoted", `auth: "` + keyID + `:` + rest + `"`, `auth: "ph:aws_access_key_id:1"`, "aws-access-key-id", 110},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := build(t)
			out, findings := scanned(t, ix, tc.text)
			if out != tc.want || strings.Contains(out, rest) {
				t.Fatalf("got  %s\nwant %s", out, tc.want)
			}
			if len(findings) != 1 || findings[0].Rule != tc.rule || findings[0].Score != tc.score || findings[0].Action != actionRedact {
				t.Fatalf("findings %+v, want one of %s at %d", findings, tc.rule, tc.score)
			}
		})
	}

	// The range Find gives is the union too.
	text := "S3_CREDENTIALS=" + keyID + ":" + rest + " # rotated"
	matches := ix.Find([]byte(text))
	if len(matches) != 1 || text[matches[0].Start:matches[0].End] != keyID+":"+rest {
		t.Fatalf("Find: %+v", matches)
	}

	// The second rule's match can begin later than the first's: the label is
	// still the higher scorer's.
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + randomString(t, alnum, 43)
	out, findings := scanned(t, ix, "auth: a1b2c3/"+token)
	if len(findings) != 1 || findings[0].Rule != "jwt" || out != "auth: "+findings[0].Placeholder {
		t.Fatalf("a token inside a longer value: %s %+v", out, findings)
	}

	// A match that only alerts never widens a replacement, and no longer keeps
	// one from being made: here a token that is only reported holds an access
	// key id, which is replaced, and nothing more than it.
	tail := randomString(t, alnum, 24)
	text = "the response held eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + keyID + "-" + tail
	out, findings = scanned(t, ix, text)
	if len(findings) != 1 || findings[0].Rule != "aws-access-key-id" || out != strings.Replace(text, keyID, findings[0].Placeholder, 1) {
		t.Fatalf("an alert around a replacement: %s %+v", out, findings)
	}
}

// A token longer than its rule allows used to lose the length the rule knew and
// keep the rest: ph:vault_token:1 and then ten characters of the token.
func TestATokenThatRunsOnIsReplacedWhole(t *testing.T) {
	ix := build(t)
	share := func() string { return randomHex(t, 32) }
	for name, tc := range map[string]struct{ token, label string }{
		"a service token ten past its length":  {fresh(t, func() string { return "hvs" + "." + randomString(t, base64URL, 130) }), "vault_token"},
		"a batch token past its length":        {fresh(t, func() string { return "hvb" + "." + randomString(t, base64URL, 340) }), "vault_token"},
		"a fine-grained token past its length": {fresh(t, func() string { return "github_pat_" + randomString(t, alnum+"_", 130) }), "github_token"},
		"a Phase token with a share too many":  {"pss_service:v2:" + share() + ":" + share() + ":" + share() + ":" + share() + ":" + share(), "phase_service_token"},
		"as long as a run may be":              {fresh(t, func() string { return "hvs" + "." + randomString(t, base64URL, maxTokenRun-4) }), "vault_token"},
	} {
		text := "the value is " + tc.token + " here"
		if out, findings := scanned(t, ix, text); len(findings) != 1 || out != "the value is "+findings[0].Placeholder+" here" || findings[0].Label != tc.label {
			t.Errorf("%s: %s %+v", name, out, findings)
		}
	}
	// Past the cap it is no token: nothing is taken, rather than a part of it.
	long := "the value is " + "hvs" + "." + randomString(t, alnum, maxTokenRun-3) + " here"
	if out, findings := scanned(t, ix, long); out != long || len(findings) != 0 {
		t.Errorf("a run past the cap: %+v", findings)
	}

	// The option that does it, on a rule of a file's own: with a charset the run
	// is followed, and without one the rule matches what it always did.
	rules, err := ParseRules([]byte("rules:\n  - id: with-run\n    regex: '\\bzz_[0-9a-f]{8}'\n    charset: 0-9a-f\n  - id: without\n    regex: '\\byy_[0-9a-f]{8}'\n  - id: by-prefix\n    prefix: xx_\n    charset: 0-9a-f\n    length: 8\n"))
	if err != nil || len(rules.Skipped()) != 0 {
		t.Fatalf("%v %+v", err, rules.Skipped())
	}
	out, _ := ix.RedactWith([]byte("zz_0123456789abcdef yy_0123456789abcdef xx_0123456789abcdef zz_01234567."), ScanOptions{Rules: rules})
	if string(out) != "ph:with_run:1 ph:without:189abcdef ph:by_prefix:1 ph:with_run:2." {
		t.Fatalf("%s", out)
	}
}

// A Google API key is public in a Firebase or Maps web app and a secret when it
// is a Gemini key. It is reported everywhere, and replaced only under a name
// that says which it is.
func TestGoogleKeysAreReportedUnlessTheNameSaysGemini(t *testing.T) {
	key := webKey(t)
	public := map[string]string{
		"a Firebase web config":    "const firebaseConfig = {\n  apiKey: \"" + key + "\",\n  authDomain: \"orders-web-1a2b3.firebaseapp.com\",\n  projectId: \"orders-web-1a2b3\"\n};",
		"google-services.json":     `{"client":[{"api_key":[{"current_key":"` + key + `"}],"oauth_client":[]}]}`,
		"a Maps script":            `<script async src="https://maps.googleapis.com/maps/api/js?key=` + key + `&callback=initMap"></script>`,
		"a public env variable":    "NEXT_PUBLIC_FIREBASE_API_KEY=" + key + "\n",
		"a Maps key":               "VITE_GOOGLE_MAPS_API_KEY=" + key,
		"public, though Gemini":    "NEXT_PUBLIC_GEMINI_API_KEY=" + key,
		"Firebase, though Google":  "FIREBASE_GOOGLE_API_KEY: " + key,
		"a keyword and no more":    "api_key = '" + key + "'",
		"with a full stop after":   "apiKey: " + key + ".",
		"in a sentence":            "the key " + key + " is the one in the browser bundle",
		"a Gemini name far before": "GEMINI_MODEL=gemini-2.0-flash and, a good deal further on in the line, the Maps key " + key,
	}
	for name, text := range public {
		ix := build(t)
		out, findings := scanned(t, ix, text)
		if out != text || len(findings) != 1 || findings[0].Rule != "google-api-key" || findings[0].Action != actionAlert || findings[0].Score != 40 {
			t.Errorf("%s: %+v\n%s", name, findings, out)
		}
	}
	secret := map[string]string{
		"GEMINI_API_KEY":         "GEMINI_API_KEY=" + key,
		"lower case":             `gemini_api_key: "` + key + `"`,
		"GOOGLE_API_KEY":         "export GOOGLE_API_KEY=" + key,
		"GOOGLE_AI":              "GOOGLE_AI_STUDIO_KEY=" + key,
		"GOOGLE_GENERATIVE_AI":   "GOOGLE_GENERATIVE_AI_API_KEY=" + key,
		"the SDK":                `client = genai.Client(api_key="` + key + `")`,
		"the header":             `curl -H "X-Goog-Api-Key: ` + key + `" -d @body.json`,
		"the API's own host":     "curl https://generativelanguage.googleapis.com/v1beta/models?key=" + key,
		"a model in the URL":     "POST /v1beta/models/gemini-2.0-flash:generateContent?key=" + key + "&alt=sse",
		"public on another name": "NEXT_PUBLIC_SITE_URL=https://acme.io GEMINI_API_KEY=" + key,
	}
	for name, text := range secret {
		ix := build(t)
		out, findings := scanned(t, ix, text)
		if len(findings) != 1 || findings[0].Rule != "google-api-key" || findings[0].Score != 70 || out != strings.Replace(text, key, "ph:google_api_key:1", 1) {
			t.Errorf("%s: %+v\n%s", name, findings, out)
		}
	}
	// As JSON values in a request: the key's own name decides.
	ix := build(t)
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]any{
		"apiKey": key, "firebase": map[string]string{"apiKey": key}, "GEMINI_API_KEY": key, "NEXT_PUBLIC_GEMINI_API_KEY": key,
	}}}})
	result := apply(ix, body)
	actions := map[string]string{}
	for _, f := range result.Rules {
		actions[f.Path] = f.Rule + " " + f.Action
	}
	if len(result.Rules) != 4 || actions["/messages/0/content/GEMINI_API_KEY"] != "google-api-key redact" || actions["/messages/0/content/apiKey"] != "google-api-key alert" ||
		actions["/messages/0/content/firebase/apiKey"] != "google-api-key alert" || actions["/messages/0/content/NEXT_PUBLIC_GEMINI_API_KEY"] != "google-api-key alert" || strings.Count(string(result.Out), key) != 3 {
		t.Fatalf("as JSON values: %v\n%s", actions, result.Out)
	}
	// A value that goes on past the key is not a Google key: the keyword rule has it.
	more := opaque(t, 24)
	if out, findings := scanned(t, build(t), "API_KEY="+key+":"+more); out != "API_KEY=ph:keyword_secret:1" || len(findings) != 1 {
		t.Fatalf("a key and more after a keyword: %s %+v", out, findings)
	}

	// The option, on a rule of a file's own: its keywords are used instead of the
	// general ones, and an exception cancels them within one name.
	rules, err := ParseRules([]byte("scoring:\n  keywords: [token]\nrules:\n  - id: own\n    regex: '\\bzz_[0-9]{8}\\b'\n    score: 40\n    keywords: [special]\n    keywords_except: [public]\n  - id: general\n    regex: '\\byy_[0-9]{8}\\b'\n    score: 40\n  - id: by-keyword\n    keyword_value: true\n    min_length: 8\n    score: 20\n"))
	if err != nil || len(rules.Skipped()) != 0 {
		t.Fatalf("%v %+v", err, rules.Skipped())
	}
	for text, want := range map[string]string{
		"token zz_12345678":          "token zz_12345678",
		"token yy_12345678":          "token ph:general:1",
		"special zz_12345678":        "special ph:own:1",
		"SPECIAL_ID=zz_12345678":     "SPECIAL_ID=ph:own:1",
		"PUBLIC_SPECIAL=zz_12345678": "PUBLIC_SPECIAL=zz_12345678",
		// The keyword rule would take this one; the rule that knows the format decides.
		"special_token=zz_12345678":        "special_token=ph:own:1",
		"public_special_token=zz_12345678": "public_special_token=zz_12345678",
		"token=zz_12345678":                "token=zz_12345678",
		"token=qq_12345678":                "token=ph:by_keyword:1",
	} {
		if out, _ := ix.RedactWith([]byte(text), ScanOptions{Rules: rules}); string(out) != want {
			t.Errorf("%q became %q, want %q", text, out, want)
		}
	}
	for name, file := range map[string]string{
		"a keyword too short":          "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n    keywords: [ab]\n  - id: b\n    regex: 'def[0-9]{3}'\n",
		"an empty exception":           "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n    keywords: [abc]\n    keywords_except: ['']\n  - id: b\n    regex: 'def[0-9]{3}'\n",
		"an exception and no keywords": "rules:\n  - id: a\n    regex: 'abc[0-9]{3}'\n    keywords_except: [public]\n  - id: b\n    regex: 'def[0-9]{3}'\n",
	} {
		if rules, err := ParseRules([]byte(file)); err != nil || rules.Len() != 1 || len(rules.Skipped()) != 1 || rules.Skipped()[0].ID != "a" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What the matcher wrote is never a candidate again, for any rule, and a
// keyword inside it is no keyword.
func TestPlaceholdersAreNeverCandidates(t *testing.T) {
	value, next := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd", opaque(t, 24)
	ix := build(t, secret{ID: "db_password", Value: value})
	twice := func(text string) (string, string) {
		once, _ := ix.Redact([]byte(text))
		again, _ := ix.Redact(once)
		return string(once), string(again)
	}
	// A rule used to match the placeholder it had just written, and number it anew.
	token := opaque(t, 30)
	once, again := twice("the hook sends secret-token:" + token + " as its password")
	if once != "the hook sends secret-token:ph:keyword_secret:1 as its password" || again != once {
		t.Fatalf("%s\n%s", once, again)
	}
	// A rule used to replace an indexed value's placeholder with one of its own.
	once, again = twice("the hook sends secret-token:" + value + " as its password")
	if once != "the hook sends secret-token:ph:secret:db_password as its password" || again != once {
		t.Fatalf("%s\n%s", once, again)
	}
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]string{"password": value, "api_token": "see " + value}}}})
	result := apply(ix, body)
	if !bytes.Contains(result.Out, []byte(`"password":"ph:secret:db_password"`)) || len(result.Rules) != 0 || len(result.Hits) != 2 {
		t.Fatalf("a placeholder under a keyword: %s %+v", result.Out, result.Rules)
	}
	if second := apply(ix, result.Out); second.Changed || !bytes.Equal(second.Out, result.Out) {
		t.Fatalf("the second pass changed it: %s", second.Out)
	}
	// The name in a placeholder is not a keyword for what follows it.
	text := "use " + value + " " + next + " as given"
	once, again = twice(text)
	if once != "use ph:secret:db_password "+next+" as given" || again != once {
		t.Fatalf("%s\n%s", once, again)
	}
	// Nor does it earn the token after it a keyword's bonus.
	bare := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + randomString(t, alnum, 43)
	if out, report := ix.Redact([]byte("ph:secret:db_password " + bare)); !bytes.Contains(out, []byte(bare)) || report.Alerts != 1 || report.Redacted != 0 {
		t.Fatalf("a keyword inside a placeholder earned a bonus: %s", out)
	}
	// A placeholder written right after a word is one still: a URL holds
	// /bot<token>/, and mysql takes -p<password>.
	bot := telegramToken(t)
	once, again = twice("https://api.telegram.org/file/bot" + bot + "/photos/file_17.jpg")
	if once != "https://api.telegram.org/file/botph:telegram_bot_token:1/photos/file_17.jpg" || again != once {
		t.Fatalf("%s\n%s", once, again)
	}
	once, again = twice("mysql -u app -p" + value + " " + next)
	if once != "mysql -u app -pph:secret:db_password "+next || again != once {
		t.Fatalf("%s\n%s", once, again)
	}
	// Text that only ends the way a placeholder begins is ordinary text.
	if out, findings := scanned(t, build(t), "graph:node:api_token="+next); out != "graph:node:api_token=ph:keyword_secret:1" || len(findings) != 1 {
		t.Fatalf("%s %+v", out, findings)
	}

	label := func(part []byte) bool { return string(part) == "github_token" }
	typed := func(part []byte) bool { return string(part) == "secret" }
	for text, want := range map[string][]placed{
		"ph:secret:db":                    {{0, 12, false}},
		"a ph:keyword_secret:12, b":       {{2, 22, false}},
		"(ph:sealed:STRIPE.KEY-1)":        {{1, 23, false}},
		"graph:node:1 morph:x:y xph:a:b":  nil,
		"-pph:secret:db botph:secret:1/x": {{2, 14, false}, {18, 29, false}},
		// A rule's placeholder is its label and digits, whatever follows it.
		"ph:github_token:12":                 {{0, 18, true}},
		"/botph:github_token:7/x":            {{4, 21, true}},
		"ph:github_token:7abc ph:secret:7ab": {{0, 17, true}, {21, 34, false}},
		"ph:github_token:x ph:github_token:": nil,
		"ph: ph:a ph:a: ph::b ph":            nil,
		"ph:a:bph:c:d":                       {{0, 8, false}},
		"ph:a:b ph:c:d":                      {{0, 6, false}, {7, 13, false}},
		"ph:" + strings.Repeat("a", 65):      nil,
		"-ph:a:b":                            {{1, 7, false}},
		"ph:a:" + strings.Repeat("b", 70):    {{0, 69, false}},
	} {
		got := placeholders([]byte(text), label, typed)
		if len(got) != len(want) {
			t.Errorf("%q: %v, want %v", text, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q: %v, want %v", text, got, want)
			}
		}
	}
}

// A first pass shortens the text and writes labels and numbers into it. Neither
// may make a second pass take what the first one left: a token that was only
// reported because its keyword was too far away, or a value that was no
// candidate until a placeholder's own characters stood in it.
func TestASecondPassTakesNothingMore(t *testing.T) {
	value := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd"
	ix := build(t, secret{ID: "db_password", Value: value})
	bare := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + randomString(t, alnum, 43)
	letters := fresh(t, func() string { return "hf" + "_" + randomString(t, asciiLetters, 34) })
	classic, key := checksummed(t, "ghp_"), webKey(t)
	for name, tc := range map[string]struct{ text, want string }{
		"a token past a long value":      {"refresh_token=" + opaque(t, 60) + " jwt=" + bare, "refresh_token=ph:keyword_secret:1 jwt=" + bare},
		"a Google key past a long value": {"GEMINI_API_KEY=" + opaque(t, 70) + " " + key, "GEMINI_API_KEY=ph:keyword_secret:1 " + key},
		// An indexed value is replaced before the rules read the text, in the
		// first pass as in the second, so the keyword is as near both times.
		"a token past an indexed value":    {"password: " + value + " " + bare, "password: ph:secret:db_password ph:jwt:1"},
		"a token with no digit in a value": {"auth: x/" + letters, "auth: x/ph:huggingface_token:1"},
		"a token in a dotted name":         {"key_secret: config." + classic, "key_secret: config.ph:github_token:1"},
		// A value that holds a placeholder is still taken for the rest of it.
		"an indexed password in a URL":  {"DSN=postgres://app:" + value + "@db.internal:5432/app", "DSN=ph:keyword_secret:1"},
		"a value before an indexed one": {"token=" + opaque(t, 24) + "/" + value, "token=ph:keyword_secret:1"},
	} {
		ix.ruleNums, ix.ruleNext = map[[macSize]byte]int{}, map[string]int{}
		once, _ := ix.Redact([]byte(tc.text))
		again, report := ix.Redact(once)
		if string(once) != tc.want || string(again) != tc.want || report.Redacted != 0 || report.Inventory != 0 {
			t.Errorf("%s:\n once  %s\n again %s\n want  %s", name, once, again, tc.want)
		}
	}
}

// Scanning text that was already rewritten changes nothing: the fake-secret
// repository, sent as tool results and as plain text, and every format's own
// samples.
func TestRewritingTwiceChangesNothing(t *testing.T) {
	fixture := censortest.NewFixture()
	var secrets []secret
	for _, entry := range fixture.Entries {
		if entry.Expect != "rule" {
			secrets = append(secrets, secret{ID: entry.ID, Type: entry.Type, Value: entry.Value})
		}
	}
	ix := build(t, secrets...)
	names := make([]string, 0, len(fixture.Files))
	for name := range fixture.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	replaced := 0
	check := func(name string, payload []byte) {
		t.Helper()
		once := apply(ix, payload)
		again := apply(ix, once.Out)
		if again.Changed || !bytes.Equal(again.Out, once.Out) || again.Report.Inventory != 0 || again.Report.Redacted != 0 {
			t.Errorf("%s: a second pass changed the text: %d inventory, %d redacted\n%s\n%s", name, again.Report.Inventory, again.Report.Redacted, once.Out, again.Out)
		}
		if third := apply(ix, again.Out); !bytes.Equal(third.Out, once.Out) {
			t.Errorf("%s: a third pass changed the text", name)
		}
		replaced += once.Report.Inventory + once.Report.Redacted
	}
	var all []string
	for _, name := range names {
		content := fixture.Files[name]
		all = append(all, content)
		check(name, []byte(content))
		check(name+" as a tool result", modelRequest("read "+name, content))
	}
	check("every file in one request", modelRequest(all...))
	for _, tc := range formatCases(t) {
		for _, sample := range tc.positives {
			check(tc.rule, []byte(sample.text))
		}
	}
	if replaced < 150 {
		t.Fatalf("only %d replacements were made to begin with", replaced)
	}
}

// secret-token: is an RFC 8959 scheme and also how an image of that name is
// tagged, so its rule only reports. A random value after it is still replaced,
// by the keyword rule.
func TestSecretTokenOnlyReports(t *testing.T) {
	ix := build(t)
	for _, text := range []string{
		"    image: ghcr.io/acme/secret-token:2024.11.19-build.412\n",
		"docker pull registry.acme.io/tools/secret-token:sha-3f2a1b9c8d7e6f50\n",
		"FROM localhost:5000/platform/secret-token:v1.4.2-alpine3.19 AS build",
	} {
		out, findings := scanned(t, ix, text)
		if out != text || len(findings) != 1 || findings[0].Rule != "secret-token-uri" || findings[0].Action != actionAlert {
			t.Errorf("%q: %+v\n%s", text, findings, out)
		}
	}
	value := opaque(t, 30)
	if out, findings := scanned(t, ix, "the hook sends secret-token:"+value+" as its password"); out != "the hook sends secret-token:ph:keyword_secret:1 as its password" || len(findings) != 1 {
		t.Fatalf("%s %+v", out, findings)
	}
	// After a keyword of its own the scheme goes with the value.
	if out, findings := scanned(t, build(t), "Authorization: Bearer secret-token:"+value); out != "Authorization: Bearer ph:keyword_secret:1" || len(findings) != 1 {
		t.Fatalf("%s %+v", out, findings)
	}
	// An image and its tag are told from the user and password of a URL, which
	// have the same shape after "//".
	token := opaque(t, 40)
	if out, _ := scanned(t, ix, "git clone https://x-access-token:"+token+"@github.com/acme/orders.git"); strings.Contains(out, token) {
		t.Fatalf("a credential in a URL was taken for an image tag: %s", out)
	}
	if out, _ := scanned(t, ix, "quay.io/acme/oauth2-proxy:"+token); out != "quay.io/acme/oauth2-proxy:"+token {
		t.Fatalf("an image tag was replaced: %s", out)
	}
}

// The general keyword rule took the names of things for the things themselves.
func TestNamesThatAreNotSecrets(t *testing.T) {
	ix := build(t)
	for _, text := range []string{
		// The five a review named.
		"          secretName: app-config-5hb67gt9kd\n",
		`  authDomain: "orders-web-1a2b3.firebaseapp.com",`,
		"tokenizer_name: sentence-transformers/all-MiniLM-L6-v2",
		"AUTH0_DOMAIN=dev-1a2b3c4d.us.auth0.com",
		`{"tokenRow":"TokenInput_tokenRow__3xK2a"}`,
		// Each word, in each way a name is written.
		"secret_name: app-config-5hb67gt9kd", "SECRET-NAME=app-config-5hb67gt9kd", "secretRef: orders-db-7fk2m9t4hc", "TOKEN_REF=orders-db-7fk2m9t4hc",
		`{"tokenizer": "bert-base-multilingual-cased-v2", "max_tokens": 4096}`, "--tokenizer google-bert/bert-base-multilingual-cased-v2",
		"auth_domain: dev-1a2b3c4d.us.auth0.com", "tokenRow: TokenRow-7fk2m9t4hc-x1", "token_id: tok-7fk2m9t4hc-2024-11", "secretId = 7fk2m9t4hc5hb67gt9kd",
		"token_type: urn-ietf-params-oauth-token-type-jwt2", "auth-type: oidc-7fk2m9t4hc-2024", "password_file: secrets/ci-deploy-2024.txt", "--token-file ci/deploy-2024-11-19.txt",
		"credentialsFile: keys/orders-prod-3f2a1b.json", "secrets_path: kv/data/orders/prod-2024-11", "token_url: login.acme.io/oauth2/v2.0/token", "authUri: accounts.acme.io/o/oauth2/v2/auth",
		"token_endpoint: login.acme.io/oauth2/v2.0/token", "tokenCount: about-4096-per-1k-chars", "password_expiry: 2026-11-19T10:22:33Z", "TOKEN_TTL=15m0s-then-refresh-2x",
		"secret_ids: 7fk2m9t4hc,5hb67gt9kd", "secretNames=app-config-5hb67gt9kd",
		// The word a name ends on, where it names a label.
		"AUTH0_CLIENT_ID=aUbeuuG2kwi8JLoJg66nSXDQ68U6Cl1W", "GOOGLE_OAUTH_CLIENT_ID=482913376120-8haew5g59795f27kfpu1ff9joh0c9327.apps.googleusercontent.com",
		"password_policy_name: corp-default-2024-q4-policy", "api_key_header_name: X-Orders-Api-Key-V2", "passwordSecretRef: orders-db-7fk2m9t4hc", "bearer_token_file: ci/deploy-2024-11-19.txt",
		`{"oauth2ClientId": "aUbeuuG2kwi8JLoJg66nSXDQ68U6Cl1W"}`,
	} {
		if out, findings := scanned(t, ix, text); out != text || len(findings) != 0 {
			t.Errorf("%q was taken: %+v", text, findings)
		}
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}})
		if result := apply(ix, body); result.Changed || len(result.Rules) != 0 {
			t.Errorf("%q was taken in a request: %+v", text, result.Rules)
		}
	}
	// As the key of a JSON value too.
	for _, name := range []string{"secretName", "tokenRow", "tokenizer", "auth_domain", "token_file", "AUTH0_CLIENT_ID", "passwordSecretRef", "tokenIds"} {
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]string{name: "x7Yz2-" + opaque(t, 24)}}}})
		if result := apply(ix, body); result.Changed || len(result.Rules) != 0 {
			t.Errorf("the JSON value under %s was taken: %+v", name, result.Rules)
		}
	}

	// These are still the names of secrets, whatever follows the keyword.
	value := opaque(t, 28)
	for _, name := range []string{
		"secretKey", "tokenValue", "SECRET_KEY_BASE", "API_TOKEN_SECRET", "passwordHash", "client_secret", "SECRET", "token", "auth_token", "TOKEN2", "password_1",
		"secret-key", "secretAccessKey", "token_refresh", "tokenRefreshSecret", "ID_TOKEN", "name_token", "TOKEN_FILE_PASSWORD", "authSecret", "AUTH0_CLIENT_SECRET", "tokens", "credentials",
		"SECRET_URL_TOKEN", "auth_db_url_password",
	} {
		for _, text := range []string{name + "=" + value, name + ": " + value, `"` + name + `": "` + value + `"`} {
			if out, findings := scanned(t, ix, text); strings.Contains(out, value) || len(findings) != 1 || findings[0].Rule != "keyword-high-entropy" {
				t.Errorf("%q was not taken: %+v", text, findings)
			}
		}
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]string{name: value}}}})
		if result := apply(ix, body); len(result.Rules) != 1 || bytes.Contains(result.Out, []byte(value)) {
			t.Errorf("the JSON value under %s was not taken: %+v", name, result.Rules)
		}
	}
	// A URL with a password in it is a credential under any name.
	for _, text := range []string{"AUTH_URL=https://admin:" + value + "@keycloak.internal/auth", "token_uri: amqps://orders:" + value + "@mq.internal:5671/orders", `{"secretRef": "redis://:` + value + `@cache:6379/0"}`} {
		if out, findings := scanned(t, ix, text); strings.Contains(out, value) || len(findings) != 1 {
			t.Errorf("%q was left: %+v", text, findings)
		}
	}
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]string{"auth_url": "https://admin:" + value + "@keycloak.internal/auth", "token_url": "https://login.acme.io/oauth2/v2.0/token"}}}})
	if result := apply(ix, body); len(result.Rules) != 1 || result.Rules[0].Path != "/messages/0/content/auth_url" || bytes.Contains(result.Out, []byte(value)) {
		t.Errorf("a URL with a password under a JSON key: %+v", result.Rules)
	}
	// "password=" ends its own name: what follows it is the value, whatever it begins with.
	if out, _ := scanned(t, ix, "Server=db;Uid=app;Password=Name"+value+";"); strings.Contains(out, value) {
		t.Errorf("a value that begins like a name's last word was left: %s", out)
	}

	for rest, want := range map[string]bool{
		"Name": true, "_name": true, "-NAME": true, ".name": true, "Names": true, "": false, "s": false, "Namespace": false, "Refresh": false, "Identity": false, "Typed": false,
		"izer": true, "IZER_NAME": true, "izers": true, "ization": false, "0_DOMAIN": true, "2ClientId": true, "_CLIENT_SECRET": false, "sFile": true, "S_PATH": true, "_KEY_BASE": false,
		"URLPath": true, "_db_url": false, "_policy_name": true, "KeyRef": true, "Hash": false, "Value": false, "_ID": true, "Id": true, "id": true, "ID2": true,
	} {
		if got := describesNoSecret([]byte(rest)); got != want {
			t.Errorf("a name going on %q: %v, want %v", rest, got, want)
		}
	}
}

// A token of three dotted parts read as a dotted name whenever none of its
// parts held a '-', and was left in the request.
func TestADottedTokenIsNotADottedName(t *testing.T) {
	ix := build(t)
	// In the shape of a Discord bot token and of a Mapbox secret token: letters,
	// digits and underscores only.
	discord := fresh(t, func() string {
		return "MTk4" + randomString(t, alnum, 20) + "." + "C" + randomString(t, alnum+"_", 4) + "7" + "." + "Z" + randomString(t, alnum+"_", 25) + "4"
	})
	mapbox := fresh(t, func() string {
		return "sk" + ".eyJ1Ijoi" + randomString(t, alnum, 60) + "." + "a" + randomString(t, alnum, 20) + "9"
	})
	for name, text := range map[string]string{"DISCORD_TOKEN=": discord, "MAPBOX_SECRET_TOKEN=": mapbox, `"bot_token": "`: discord} {
		if out, findings := scanned(t, ix, name+text); strings.Contains(out, text) || len(findings) != 1 || findings[0].Rule != "keyword-high-entropy" {
			t.Errorf("%s%s was left: %+v", name, text, findings)
		}
	}
	// Names stay names: a reference, a call, a chain of fields.
	for _, text := range []string{
		"STRIPE_SECRET_KEY=process.env.STRIPE_SECRET_KEY_2",
		"token := base64.StdEncoding.EncodeToString(raw)",
		"auth = base64.RawURLEncoding.EncodeToString(sum[:])",
		"secret: config.credentials.accessTokenV2",
		"password = settings.DATABASES.default_password1",
		"token: this.props.session.accessToken2",
	} {
		if out, findings := scanned(t, ix, text); out != text || len(findings) != 0 {
			t.Errorf("%q was taken: %+v", text, findings)
		}
	}
	for value, want := range map[string]bool{
		"MTk4NjIyNDgz" + "NDcxOTI1MjQ4." + "Cl2FMQ" + ".ZnCjm1XVW7" + "vRze4b7Cq4se7kKWs": true,
		"a1b2c3d4.e5f6g7h8.i9j0":            true,
		"a1b2c3d4.e5f6g7h8.i9":              false, // 18 characters
		"base64.StdEncoding.EncodeToString": false, // digits in one place
		"aaaaaaaa.bbbbbbbb.cccccccc":        false,
		"a1b2c3d4.e5f6g7h8":                 false, // two parts
		"a1b2.c3d4.e5f6.g7h8.i9j0k1l2":      false, // five
		"a1b2c3d4..e5f6g7h8i9j0k1l2":        false,
		"a1b2c3d4.e5f6g7h8.i9j0k1l2.":       false,
		"a1b2c3d4.e5f6+7h8.i9j0k1l2":        false,
	} {
		if got := dottedToken([]byte(value)); got != want {
			t.Errorf("%s: %v, want %v", value, got, want)
		}
	}
}

// Two rules only gave another label to what the keyword rule replaces anyway,
// and one of them left part of the value behind.
func TestRulesThatOnlyRelabelAreGone(t *testing.T) {
	for _, id := range []string{"azure-storage-key-keyword", "twilio-api-key-sid"} {
		if _, err := DefaultRules().Only(id); err == nil {
			t.Errorf("%s is still a rule", id)
		}
	}
	ix := build(t)
	// A SID random enough for the keyword rule, which wants 3.5 bits a byte: one
	// in three of 32 hex digits is under that, and is then left as it is.
	sid := fresh(t, func() string {
		for {
			if value := "SK" + randomString(t, lowerHex, 32); entropy(value) >= 3.6 {
				return value
			}
		}
	})
	longKey := fresh(t, func() string { return randomString(t, base64Std, 86) + "==" })
	for name, text := range map[string]string{"TWILIO_API_KEY=": sid, `const apiKeySid = "`: sid, "JWT_SECRET=": longKey, "password_hash: ": longKey, `primary_access_key = "`: longKey, "AZURE_STORAGE_ACCESS_KEY=": longKey} {
		out, findings := scanned(t, ix, name+text)
		if out != name+"ph:keyword_secret:1" && !strings.HasPrefix(out, name+"ph:keyword_secret:") || len(findings) != 1 || findings[0].Rule != "keyword-high-entropy" {
			t.Errorf("%s: %s %+v", name, out, findings)
		}
	}
	// A SID is an identifier: with no keyword it is not touched.
	if text := "created " + sid + " for the support app"; true {
		if out, findings := scanned(t, ix, text); out != text || len(findings) != 0 {
			t.Errorf("%+v", findings)
		}
	}
	// A bot token is taken by its own rule only when it is the whole value.
	bot, more := telegramToken(t), opaque(t, 24)
	if out, findings := scanned(t, ix, "TELEGRAM_BOT_TOKEN="+bot); out != "TELEGRAM_BOT_TOKEN=ph:telegram_bot_token:1" || len(findings) != 1 {
		t.Errorf("%s %+v", out, findings)
	}
	for _, text := range []string{"BOT_TOKEN=" + bot + ":" + more, "BOT_TOKEN=" + bot + "/" + more, "BOT_TOKEN=" + bot + "."} {
		if out, findings := scanned(t, build(t), text); out != "BOT_TOKEN=ph:keyword_secret:1" || len(findings) != 1 {
			t.Errorf("%q: %s %+v", text, out, findings)
		}
	}
}

// The exemption for text a provider signed holds where the providers put that
// text and nowhere else in the request's own JSON.
func TestSignedExemptionHoldsOnlyWhereProvidersPutIt(t *testing.T) {
	value := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd"
	ix := build(t, secret{ID: "db", Type: "secret", Value: value})
	token := githubToken(t)
	thinking := map[string]any{"type": "thinking", "thinking": "the value is " + value + " and " + token, "signature": "c2lnbmVk"}
	bodies := map[string]any{
		"a function response shaped like a thinking block": map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{
			map[string]any{"functionResponse": map[string]any{"name": "read_file", "response": thinking}}}}}},
		"a function response with data": map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{
			map[string]any{"functionResponse": map[string]any{"name": "fetch", "response": map[string]any{"type": "redacted_thinking", "data": value + " " + token}}}}}}},
		"a function response with encrypted_content": map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{
			map[string]any{"functionResponse": map[string]any{"name": "kms", "response": map[string]any{"encrypted_content": value + " " + token}}}}}}},
		"a tool's input": map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "tool_use", "id": "t1", "name": "store", "input": thinking}}}}},
		"a block inside a tool result": map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": []any{thinking}}}}}},
		"metadata":                          map[string]any{"metadata": thinking, "messages": []any{}},
		"the system prompt":                 map[string]any{"system": []any{thinking}, "messages": []any{}},
		"content that is one block":         map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": thinking}}},
		"a message that is itself a block":  map[string]any{"messages": []any{thinking}},
		"messages that is one object":       map[string]any{"messages": map[string]any{"content": []any{thinking}}},
		"content of an input item":          map[string]any{"input": []any{map[string]any{"role": "assistant", "content": []any{thinking}}}},
		"encrypted_content deeper in input": map[string]any{"input": []any{map[string]any{"type": "function_call_output", "output": map[string]any{"encrypted_content": value + " " + token}}}},
		"encrypted_content holding more":    map[string]any{"input": []any{map[string]any{"type": "reasoning", "encrypted_content": map[string]any{"plaintext": value + " " + token}}}},
		"encrypted_content in a list":       map[string]any{"input": []any{map[string]any{"type": "reasoning", "encrypted_content": []any{value + " " + token}}}},
		"input that is one object":          map[string]any{"input": map[string]any{"encrypted_content": value + " " + token}},
		"encrypted_content in a message":    map[string]any{"messages": []any{map[string]any{"role": "assistant", "encrypted_content": value + " " + token}}},
		"encrypted_content at the top":      map[string]any{"encrypted_content": value + " " + token, "messages": []any{}},
	}
	for name, body := range bodies {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		out, report, err := ix.RewriteJSON(raw, ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte(value)) || bytes.Contains(out, []byte(token)) || report.Left != 0 || report.Inventory != 1 || report.Redacted != 1 || !json.Valid(out) {
			t.Errorf("%s: left %d, inventory %d, redacted %d\n%s", name, report.Left, report.Inventory, report.Redacted, out)
		}
	}
	// The two places that are honoured, whatever the order of a block's members.
	for name, raw := range map[string]string{
		"a thinking block":          `{"messages":[{"role":"assistant","content":[{"type":"text","text":"so"},{"signature":"` + value + `","thinking":"the token is ` + token + `","type":"thinking"}]}]}`,
		"a redacted thinking block": `{"messages":[{"role":"user","content":"go on"},{"role":"assistant","content":[{"data":"` + value + ` ` + token + `","type":"redacted_thinking"}]}]}`,
		"encrypted reasoning":       `{"input":[{"role":"user","content":"go on"},{"type":"reasoning","summary":[],"encrypted_content":"` + value + ` ` + token + `"}]}`,
	} {
		out, report, err := ix.RewriteJSON([]byte(raw), ScanOptions{})
		if err != nil || !bytes.Equal(out, []byte(raw)) || report.Changed || report.Left != 2 || report.Inventory != 0 || report.Redacted != 0 {
			t.Errorf("%s: changed %v, left %d, inventory %d, redacted %d (%v)", name, report.Changed, report.Left, report.Inventory, report.Redacted, err)
		}
	}
	// A block of another type in the honoured place is ordinary text.
	raw := `{"messages":[{"role":"assistant","content":[{"type":"text","thinking":"` + value + `","signature":"` + token + `","data":"` + value + `"}]}]}`
	if out, report, _ := ix.RewriteJSON([]byte(raw), ScanOptions{}); bytes.Contains(out, []byte(value)) || bytes.Contains(out, []byte(token)) || report.Left != 0 {
		t.Errorf("a text block with a thinking member: %s", out)
	}
}

// A token written after an escape follows a letter or a digit, so the word
// boundary its rule begins with did not hold, and it was missed.
func TestATokenAfterAnEscapeIsFound(t *testing.T) {
	ix := build(t)
	classic := checksummed(t, "ghp_")
	anthropic := fresh(t, func() string { return "sk-" + "ant-api03-" + randomString(t, base64URL, 93) + "AA" })
	keyID := awsKeyIDText(t)
	for name, tc := range map[string]struct{ text, secret string }{
		"a log line in a string":       {`{"log":"deploy started\n` + classic + `\n"}` + "\n" + `{"log":"second line"}`, classic},
		"after a tab":                  {`"cols\t` + classic + `"`, classic},
		"after a carriage return":      {`line one\r` + keyID + `\r\n`, keyID},
		"in a string of source":        {`print("key:\n` + anthropic + `")`, anthropic},
		"escaped twice":                {`{\"log\":\"start\\n` + classic + `\"}`, classic},
		"a percent-encoded =":          {"GET /cb?next=%2Fhome%3Faccess_token%3D" + classic + "%26x%3D1", classic},
		"a percent-encoded space":      {"Authorization%3A%20Bearer%20" + classic, classic},
		"a percent-encoded line break": {"body=first%0A" + keyID + "%0d%0a", keyID},
		"lower-case hex":               {"q=%3d" + keyID + "&r=1", keyID},
	} {
		out, findings := scanned(t, ix, tc.text)
		if len(findings) != 1 || out != strings.Replace(tc.text, tc.secret, findings[0].Placeholder, 1) {
			t.Errorf("%s: %+v\n%s", name, findings, out)
		}
	}
	// As the model request carries it: NDJSON inside a JSON string.
	logs := `{"log":"deploy started\n` + classic + `\n"}` + "\n" + `{"log":"second line"}`
	result := apply(ix, modelRequest(logs))
	if bytes.Contains(result.Out, []byte(classic)) || len(result.Rules) != 1 || !json.Valid(result.Out) {
		t.Fatalf("in a request: %+v", result.Rules)
	}
	// Where it is found is where it is in the text as given.
	text := "x%3D" + classic + "%26"
	if matches := ix.Find([]byte(text)); len(matches) != 1 || text[matches[0].Start:matches[0].End] != classic {
		t.Fatalf("Find: %+v", matches)
	}

	// An escape that stands for a letter, a digit or '_' is still inside a word,
	// and so is whatever only looks like an escape.
	for name, text := range map[string]string{
		"a percent-encoded letter":     "id=%41" + classic,
		"a percent-encoded digit":      "id=%37" + keyID,
		"a percent-encoded underscore": "id=x%5F" + classic,
		"not hex":                      "100%zz" + classic,
		"one hex digit":                "100%4" + classic,
		"letters and no backslash":     "then" + classic,
		"another letter escaped":       `\x` + classic,
		"a unicode escape":             `\u0041` + keyID,
		"a backslash further back":     `\ nn` + classic,
	} {
		if out, findings := scanned(t, ix, text); out != text || len(findings) != 0 {
			t.Errorf("%s: a rule matched inside a word: %+v", name, findings)
		}
	}
	for text, want := range map[string]int{`a\nXY`: '\n', `a\tXY`: '\t', `a\rXY`: '\r', "a%3DXY": '=', "a%0aXY": '\n', "a%41XY": 'A', `a\"XY`: -1, `a\\XY`: -1, `a\/XY`: -1, "a%4XY": -1, "anXY": -1, "nXY": -1, "%3XY": -1} {
		b, ok := escapeBefore([]byte(text), len(text)-2)
		if got := map[bool]int{true: int(b), false: -1}[ok]; got != want {
			t.Errorf("%q: %d, want %d", text, got, want)
		}
	}
}

// fixedText is the same text every run: made here rather than written out, so
// that no file holds it.
func fixedText(label, alphabet string, n int) string {
	var out []byte
	for counter := 0; len(out) < n; counter++ {
		sum := sha256.Sum256([]byte(label + string(rune('a'+counter))))
		for _, b := range sum {
			if len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}

// One chunk of a base64 or hex form of a value covers nine or six of its
// bytes. When those are hex digits it carries 36 bits or fewer, and megabytes
// of text of the same kind repeat such a chunk by chance: that is what made
// TestFalsePositivesOnOrdinaryText fail about once in 330 runs. Such a chunk
// alone is no match; a second one next to it is.
func TestOneThinChunkIsNoMatch(t *testing.T) {
	hexValue, other := fixedText("thin value", lowerHex, 64), fixedText("other text", lowerHex, 63)
	wideValue := fixedText("wide value", alnum, 64)
	// Scheme 1 is what this rule was written for, and entries stored under it
	// are still matched: scheme 2 stores these forms in pairs, and
	// TestHexFormsAreStoredInPairs says what a piece of one does there.
	ix := buildScheme(t, 1, secret{ID: "hexkey", Value: hexValue}, secret{ID: "wide", Value: wideValue})
	encode := base64.StdEncoding.EncodeToString
	// Each form from its second chunk on, at a chunk that the index does not
	// mark as too plain to count: twelve characters of hex often are.
	from := func(form string) string {
		for at := chunkSize; at+2*chunkSize < len(form); at += chunkSize {
			if entropy(form[at:at+chunkSize]) >= weakChunkEntropy {
				return form[at:]
			}
		}
		t.Fatalf("no chunk of %s counts", form)
		return ""
	}
	whole := encode([]byte(hexValue))
	form, shifted := from(whole), from(encode([]byte("ab" + hexValue))[3:])
	wholeHex := hex.EncodeToString([]byte(wideValue))
	hexForm, wideForm, raw := from(wholeHex), from(encode([]byte(wideValue))), from(hexValue)
	// What chance writes: base64 over other hex text, one chunk of it equal to
	// a chunk of the indexed value's form.
	ordinary := encode([]byte(other))
	chance := ordinary[:12] + form[:12] + ordinary[24:]
	for name, tc := range map[string]struct {
		text    string
		found   string // the placeholder, or none
		partial bool
	}{
		"one chunk of base64 over hex":             {"blob " + form[:12] + " end", "", false},
		"one chunk, in ordinary base64 over hex":   {"blob " + chance + "\n", "", false},
		"one chunk at another alignment":           {"blob " + shifted[:12] + " end", "", false},
		"one chunk and part of the next":           {"blob " + form[:21] + " end", "", false},
		"two chunks of base64 over hex":            {"blob " + form[:24] + " end", "ph:secret:hexkey", true},
		"two chunks at another alignment":          {"blob " + shifted[:24] + " end", "ph:secret:hexkey", true},
		"the whole of it":                          {"blob " + whole + " end", "ph:secret:hexkey", false},
		"the whole of it, inside more":             {"blob " + encode([]byte("ab"+hexValue+"cd")) + " end", "ph:secret:hexkey", false},
		"one chunk of the hex form":                {"blob " + hexForm[:12] + " end", "", false},
		"two chunks of the hex form":               {"blob " + hexForm[:24] + " end", "ph:secret:wide", true},
		"the whole hex form":                       {"blob " + wholeHex + " end", "ph:secret:wide", false},
		"one chunk of base64 over letters, digits": {"blob " + wideForm[:12] + " end", "ph:secret:wide", true},
		"one chunk of the value itself":            {"id " + raw[:12] + " end", "ph:secret:hexkey", true},
	} {
		out, report := ix.Redact([]byte(tc.text))
		switch {
		case tc.found == "":
			if string(out) != tc.text || len(report.Findings) != 0 {
				t.Errorf("%s: matched: %+v", name, report.Findings)
			}
		case report.Inventory != 1 || len(report.Findings) != 1 || report.Findings[0].Placeholder != tc.found || report.Findings[0].Partial != tc.partial ||
			!strings.HasPrefix(string(out), strings.Fields(tc.text)[0]+" "+tc.found):
			t.Errorf("%s: %+v\n%s", name, report.Findings, out)
		}
	}

	for name, tc := range map[string]struct {
		chunk string
		class *[256]bool
		thin  bool
	}{
		"base64 over hex":                {encode([]byte("0123456789abcdef01"))[:12], &classB64, true},
		"base64 over hex, off by a byte": {encode([]byte("x0123456789abcdef01"))[2:14], &classB64, true},
		"base64 over digits":             {encode([]byte("482913376120482913"))[:12], &classB64, true},
		"base64 over lower case, digits": {encode([]byte("k7fq2m9t4hcx8w1zp3"))[:12], &classB64, true},
		"base64 over letters and digits": {encode([]byte("Zq8Lm2Zr6Tx4Nb9Wc1"))[:12], &classB64, false},
		"base64url over punctuation":     {base64.URLEncoding.EncodeToString([]byte("p@ss/w0rd!+Zq8#Lm2"))[:12], &classB64URL, false},
		"base64 over bytes":              {encode([]byte{0x01, 0xfe, 0x80, 0x7f, 0x00, 0xc3, 0x28, 0x99, 0xab})[:12], &classB64, false},
		"hex over letters and digits":    {hex.EncodeToString([]byte("Zq8Lm2")), &classHex, true},
		"hex over punctuation":           {hex.EncodeToString([]byte("p@ss/w")), &classHex, true},
		"hex over bytes":                 {hex.EncodeToString([]byte{0x01, 0xfe, 0x80, 0x7f, 0x00, 0xc3}), &classHex, false},
	} {
		if bits := chunkBits([]byte(tc.chunk), tc.class); (bits < minPartialBits) != tc.thin {
			t.Errorf("%s: %.1f bits", name, bits)
		}
	}
}
