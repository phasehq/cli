package censor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A value that is JSON with no string in it, as a Solana keypair file is, is
// indexed whole. A tool result that is that JSON, or holds it as a member, is
// walked as JSON, which reads strings only: the value is found there all the
// same.
func TestAJSONValueWithoutStringsIsFoundInsideAString(t *testing.T) {
	numbers := make([]string, 64)
	for i, b := range randomBytes(t, 64) {
		numbers[i] = strconv.Itoa(int(b))
	}
	keypair := "[" + strings.Join(numbers, ",") + "]"
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "sol", Value: keypair}, secret{ID: "pw", Value: password})
	for name, tc := range map[string]struct {
		text string
		hits int
	}{
		"the whole string":        {keypair, 1},
		"a member of an object":   {`{"path":"id.json","keypair":` + keypair + `}`, 1},
		"next to a string":        {`{"password":"` + password + `","keypair":` + keypair + `}`, 2},
		"after text that is none": {"cat id.json\n" + keypair, 1},
	} {
		r := apply(ix, modelRequest(tc.text))
		if bytes.Contains(r.Out, []byte(keypair)) || bytes.Contains(r.Out, []byte(password)) || len(r.Hits) != tc.hits || !json.Valid(r.Out) {
			t.Errorf("%s: %d hits\n%s", name, len(r.Hits), r.Out)
		}
		if again := apply(ix, r.Out); again.Changed || !bytes.Equal(again.Out, r.Out) {
			t.Errorf("%s: a second pass changed the text\n%s", name, again.Out)
		}
	}
	// The string is reported as the place, with nothing after the '#'.
	r := apply(ix, modelRequest(keypair))
	if len(r.Hits) != 1 || r.Hits[0].Path != "/messages/2/content/0/content#" || r.Hits[0].Placeholder != "ph:secret:sol" || r.Hits[0].Partial {
		t.Errorf("findings: %+v", r.Hits)
	}
	// JSON in a string that holds nothing indexed is left exactly as it was.
	clean := modelRequest(`{"exit_code":0,"lines":[1,2,3,4,5,6,7,8,9,10,11,12],"stdout":"nothing to see"}`)
	if r := apply(ix, clean); r.Changed || !bytes.Equal(r.Out, clean) || len(r.Hits) != 0 {
		t.Errorf("clean JSON was changed: %s", r.Out)
	}
}

// A URL with a password in it is a credential wherever it is kept. As a leaf of
// a JSON value it is indexed like any other leaf, and its password on its own
// as well; a URL without one is still left out as public.
func TestAURLWithAPasswordInAJSONValueIsProtected(t *testing.T) {
	password := randomString(t, alnum, 24)
	remote := "https://deploy:" + password + "@git.internal/repo"
	value := `{"docs":"https://docs.internal/deploy/runbook","upstream":"` + remote + `"}`
	ix, entries := buildWithEntries(t, newKey(t), secret{ID: "cfg", Value: value})
	if got := entries["cfg"].Unprotected; len(got) != 1 || got[0] != (Unprotected{Part: "leaf:0", Reason: ReasonPublicLeaf}) {
		t.Fatalf("unprotected: %+v", got)
	}
	// Only indexed values are looked for, so no rule does the work.
	only, err := DefaultRules().Only("npm-token")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"the URL":            "git remote -v\norigin\t" + remote + " (fetch)",
		"the password alone": "the deploy password is " + password + " for now",
	} {
		out, report := ix.RedactWith([]byte(text), ScanOptions{Rules: only})
		if bytes.Contains(out, []byte(password)) || report.Inventory != 1 || report.Findings[0].Part != "leaf:1" {
			t.Errorf("%s: %+v\n%s", name, report.Findings, out)
		}
	}
	for _, text := range []string{
		"see https://docs.internal/deploy/runbook before a deploy",
		"git clone https://git.internal/repo and https://deploy@git.internal/repo",
	} {
		if out, report := ix.RedactWith([]byte(text), ScanOptions{Rules: only}); string(out) != text || report.Inventory != 0 {
			t.Errorf("a public URL was replaced: %s", out)
		}
	}
}

// holdsPiece reports whether out still holds n bytes in a row of the value.
func holdsPiece(out []byte, value string, n int) bool {
	for i := 0; i+n <= len(value); i++ {
		if bytes.Contains(out, []byte(value[i:i+n])) {
			return true
		}
	}
	return false
}

func lineForms(e *Entries) int {
	lines := 0
	for _, f := range e.Forms {
		if f.Form == formLine {
			lines++
		}
	}
	return lines
}

// Of a value of several lines, only a line that is a secret in itself is
// indexed on its own: a line of a PEM or base64 body, or a random token. A line
// of words is not, or it would be replaced wherever it is written.
func TestOnlySecretLinesOfAMultilineValueAreIndexedAlone(t *testing.T) {
	for line, want := range map[string]bool{
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj": true,
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==":                     true,
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": true,
		"Zq8Lm2-Zr6Tx4_Nb9Wc1":          true,
		"JBSWY3DPEHPK3PXP":              true,
		"apiVersion: v1":                false,
		"kind: Config":                  false,
		"server: https://10.0.0.1:6443": false,
		"certificate-authority-data:":   false,
		"kubernetes-admin":              false,
		"NODE_ENV=production":           false,
		"-----BEGIN PRIVATE KEY-----":   false,
		"Zq8Lm2+Zr6Tx4_Nb9Wc1":          false,
		"Zq8Lm2Zr6Tx4Nb9Wc1===":         false,
	} {
		if secretLine(line) != want {
			t.Errorf("secretLine(%q) is %v", line, !want)
		}
	}
	only, err := DefaultRules().Only("npm-token")
	if err != nil {
		t.Fatal(err)
	}
	redact := func(ix *Index, text string) []byte {
		out, _ := ix.RedactWith([]byte(text), ScanOptions{Rules: only})
		return out
	}

	// A line of words between two secrets, placed so that no chunk of another
	// form lies whole inside it: only its own form could find it elsewhere.
	first, last := randomString(t, alnum, 37), randomString(t, alnum, 37)
	ix, entries := buildWithEntries(t, newKey(t), secret{ID: "notes", Value: first + "\nkind: Config\n" + last})
	if got := lineForms(entries["notes"]); got != 2 {
		t.Errorf("%d lines of the value are indexed alone, want its 2 tokens", got)
	}
	// The line before it ends in a character no token ends in: the chunk that
	// holds the token's last character and the start of the line cannot match.
	manifest := "---\nkind: Config\nclusters: []\n"
	if out := redact(ix, manifest); string(out) != manifest {
		t.Errorf("a line of words was replaced elsewhere:\n%s", out)
	}
	for _, token := range []string{first, last} {
		if out := redact(ix, "    "+token+"\n"); bytes.Contains(out, []byte(token)) {
			t.Errorf("a token line was not found alone: %s", out)
		}
	}

	// A private key: every line of its body is still found alone, and the
	// armour is not.
	privateKey := fakePEM(t)
	body := strings.Split(strings.TrimSpace(privateKey), "\n")
	body = body[1 : len(body)-1]
	ix, entries = buildWithEntries(t, newKey(t), secret{ID: "tls", Value: privateKey})
	if got := lineForms(entries["tls"]); got != len(body) {
		t.Errorf("%d lines of the key are indexed alone, want %d", got, len(body))
	}
	for _, line := range body {
		if out := redact(ix, "  "+line+"\n"); bytes.Contains(out, []byte(line)) {
			t.Errorf("a line of the key was not found alone: %s", out)
		}
	}
	if armour := "-----BEGIN PRIVATE KEY-----\n"; string(redact(ix, armour)) != armour {
		t.Error("the armour was replaced")
	}

	// A service account key: the lines of the private key in it likewise.
	account, accountKey := gcpKey(t)
	ix = build(t, secret{ID: "gcp", Value: account})
	for _, line := range strings.Split(strings.TrimSpace(accountKey), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if out := redact(ix, line+"\n"); bytes.Contains(out, []byte(line)) {
			t.Errorf("a line of the account's key was not found alone: %s", out)
		}
	}

	// A kubeconfig has no line that is a secret in itself, so none is indexed
	// alone. Its key data and its token are found all the same: whole, cut out
	// of it, and in pieces.
	keyData := base64.StdEncoding.EncodeToString([]byte(privateKey))
	token := randomString(t, alnum, 40)
	kubeconfig := "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    certificate-authority-data: " +
		base64.StdEncoding.EncodeToString(randomBytes(t, 300)) + "\n    server: https://10.0.0.1:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    client-key-data: " +
		keyData + "\n    token: " + token + "\n"
	ix, entries = buildWithEntries(t, newKey(t), secret{ID: "kc", Value: kubeconfig})
	if got := lineForms(entries["kc"]); got != 0 {
		t.Errorf("%d lines of the kubeconfig are indexed alone", got)
	}
	for name, text := range map[string]string{
		"the whole file":        "cat ~/.kube/config\n" + kubeconfig,
		"the key data alone":    keyData + "\n",
		"the key data's line":   "    client-key-data: " + keyData + "\n",
		"a piece of key data":   "data: " + keyData[101:161] + "\n",
		"the token alone":       token,
		"the token's line":      "    token: " + token + "\n",
		"the token in a header": "Authorization: Bearer " + token + "\n",
	} {
		out := redact(ix, text)
		if holdsPiece(out, keyData, 24) || holdsPiece(out, token, 24) || !bytes.Contains(out, []byte("ph:secret:kc")) {
			t.Errorf("%s: something of the kubeconfig was left\n%s", name, out)
		}
	}
}

// A data: URI is skipped as an image or a file only while base64 is all that
// follows its header. Text written after one, in the same string, is read.
func TestTextAfterADataURIIsRead(t *testing.T) {
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "pw", Value: password})
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(randomBytes(t, 13000))
	r := apply(ix, modelRequest(image+"\nerror: login failed for password "+password))
	if bytes.Contains(r.Out, []byte(password)) || len(r.Hits) != 1 || r.Report.SkippedBinary != 0 {
		t.Errorf("text after an image: %d hits, %d skipped", len(r.Hits), r.Report.SkippedBinary)
	}
	if r := apply(ix, modelRequest(image)); r.Changed || r.Report.SkippedBinary != 1 {
		t.Errorf("an image alone: changed %v, %d skipped", r.Changed, r.Report.SkippedBinary)
	}
	// A field of a protobuf message is held to the same.
	message := protoString(nil, 1, []byte(image+" password "+password))
	out, report := ix.RewriteBinary(message, ScanOptions{})
	if bytes.Contains(out, []byte(password)) || report.Inventory != 1 || len(out) != len(message) {
		t.Errorf("text after an image in a message: %d found", report.Inventory)
	}
}

// One call inflates only so much. A string scanned once that budget was spent
// is not remembered as clean: the next request has a budget of its own, and
// reads it.
func TestAScanThatRanOutOfInflateBudgetIsNotCached(t *testing.T) {
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "pw", Value: password})
	filler := strings.Repeat("ordinary log line number seven\n", 40)
	blob := base64.StdEncoding.EncodeToString(gzipped(t, []byte(filler+"password: "+password+"\n"+filler)))
	release := "helm release: " + blob + "\n" + strings.Repeat("release notes follow. ", 20)
	if len(release) < cacheMinBlock {
		t.Fatalf("the string is %d bytes, too short to be cached", len(release))
	}
	bomb := base64.StdEncoding.EncodeToString(gzipped(t, make([]byte, 1<<20)))
	var texts []string
	for i := 0; i < 80; i++ {
		texts = append(texts, fmt.Sprintf("blob %d: %s", i, bomb))
	}
	if r := apply(ix, modelRequest(append(texts, release)...)); len(r.Hits) != 0 {
		t.Fatalf("the budget was not spent before the release was read: %d hits", len(r.Hits))
	}
	r := apply(ix, modelRequest(release))
	if len(r.Hits) != 1 || bytes.Contains(r.Out, []byte(blob)) || r.Report.CacheHits != 0 {
		t.Errorf("the next request: %d hits, %d from the cache", len(r.Hits), r.Report.CacheHits)
	}
	// Read with a budget, it is cached like any other string.
	if r := apply(ix, modelRequest(release)); len(r.Hits) != 1 || r.Report.CacheHits != 1 {
		t.Errorf("a third request: %d hits, %d from the cache", len(r.Hits), r.Report.CacheHits)
	}
}

// gzip data can be several members one after another, as cat a.gz b.gz makes
// it and gunzip reads it. Every member is inflated and scanned, and bytes after
// the last that begin no member do not spoil what was read.
func TestEveryGzipMemberIsRead(t *testing.T) {
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "pw", Value: password})
	filler := strings.Repeat("ordinary log line number seven\n", 40)
	clean := gzipped(t, []byte(filler))
	secret := gzipped(t, []byte(filler+"login with password "+password+"\n"+filler))
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, data := range map[string][]byte{
		"the second of two members":  join(clean, secret),
		"the last of three members":  join(clean, clean, secret),
		"a member and other bytes":   join(secret, []byte("bytes that begin no member")),
		"two members and such bytes": join(clean, secret, []byte{0, 1, 2, 3}),
	} {
		out, report := ix.Redact([]byte("log: " + base64.StdEncoding.EncodeToString(data) + "\n"))
		if string(out) != "log: ph:secret:pw\n" || report.Inventory != 1 || report.Findings[0].Form != "base64>gzip>raw" {
			t.Errorf("%s: %+v\n%.80s", name, report.Findings, out)
		}
	}
	// Members that hold nothing are still nothing.
	text := "log: " + base64.StdEncoding.EncodeToString(join(clean, clean)) + "\n"
	if out, report := ix.Redact([]byte(text)); string(out) != text || report.Inventory != 0 {
		t.Errorf("clean members: %+v", report.Findings)
	}
}

// Percent escapes are written with digits in either case: %2F by Go and most
// libraries, %2f by others. A value is found in a URL whichever was used.
func TestPercentEscapesInEitherCaseAreFound(t *testing.T) {
	for _, value := range []string{"ab/CD+ef?GH!", "Zq7/Lp+3?mW!xR9&tY4#kB2=", "pass word/" + randomString(t, alnum, 12)} {
		ix := build(t, secret{ID: "pw", Value: value})
		for _, escaped := range []string{url.QueryEscape(value), url.PathEscape(value), strings.ReplaceAll(url.QueryEscape(value), "+", "%20")} {
			for _, written := range []string{escaped, lowerEscapes(escaped)} {
				text := "GET https://api.example.com/v1/items?q=" + written + "&page=2"
				out, report := ix.Redact([]byte(text))
				if want := "GET https://api.example.com/v1/items?q=ph:secret:pw&page=2"; string(out) != want || report.Inventory != 1 || report.Findings[0].Partial {
					t.Errorf("%s: %+v\n%s", written, report.Findings, out)
				}
			}
		}
	}
	if got := lowerEscapes("a%2Fb%3D%E2%9C%93%25"); got != "a%2fb%3d%e2%9c%93%25" {
		t.Errorf("lowerEscapes: %s", got)
	}
}

// Find lists MaxFindings matches at most. A crowd of matches that only alert
// does not keep an indexed value, or one of Phase's own tokens, that comes
// after them off the list: the first of every kind is always on it, in its
// place.
func TestTheFindingsCapNeverHidesAKindOfFinding(t *testing.T) {
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "pw", Value: password})
	token := "pss_user:v1:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	for _, headers := range []int{10, MaxFindings + 100} {
		text := strings.Repeat("-----BEGIN PRIVATE KEY-----\n", headers) + "pw " + password + "\ntoken " + token + "\n"
		matches := ix.Find([]byte(text))
		if want := min(headers+2, MaxFindings); len(matches) != want {
			t.Fatalf("%d headers: %d matches, want %d", headers, len(matches), want)
		}
		found := map[string]string{}
		for i, m := range matches {
			if i > 0 && m.Start < matches[i-1].Start {
				t.Fatalf("%d headers: the matches are out of order at %d", headers, i)
			}
			if m.Kind == kindInventory || m.Label == "phase_pat" {
				found[m.Kind+m.Label] = text[m.Start:m.End]
			}
		}
		if found[kindInventory] != password || found[kindRule+"phase_pat"] != token {
			t.Errorf("%d headers: the value or the token is not listed", headers)
		}
	}
}

// A piece of a value is looked for wherever one of its chunks verifies. A try
// that came to nothing, at a token's type prefix say, does not keep a later
// piece of the same value in the same place from being found.
func TestAPieceAfterARejectedOneIsFound(t *testing.T) {
	for name, prefix := range map[string]string{
		"after a type prefix":  "common-pass-",
		"after a random start": randomString(t, alnum, 12),
		"after other text":     "",
	} {
		value := prefix + randomString(t, alnum, 36)
		if prefix == "" {
			value = randomString(t, alnum, 48)
		}
		ix := build(t, secret{ID: "v", Value: value})
		masked := value[:12] + "************" + value[24:]
		if prefix == "" {
			masked = "xxxxxxxxxxxx************" + value[24:]
		}
		out, report := ix.Redact([]byte("log: " + masked + " done"))
		if bytes.Contains(out, []byte(value[24:])) || report.Inventory == 0 {
			t.Errorf("%s: the end of the value was left: %d found\n%s", name, report.Inventory, out)
		}
	}
}

// When only a piece of a value is there, what is replaced beyond its verified
// chunks is the chunk cut short at each end: eleven bytes at most on each side.
// Text that merely stands next to a piece of a long value stays.
func TestAPartialMatchIsWidenedByLessThanAChunk(t *testing.T) {
	// The first chunk is found alone below, so it must not be one of the few
	// that are too plain to count.
	value := randomString(t, alnum, 256)
	for entropy(value[:chunkSize]) < weakChunkEntropy {
		value = randomString(t, alnum, 256)
	}
	ix := build(t, secret{ID: "big", Value: value})
	link := "https://example.com/some/long/path/with/many/segments/and/query?x=1&y=2"
	for name, tc := range map[string]struct{ text, want string }{
		"text after the first chunk":  {"see " + value[:12] + link + " end", "see ph:secret:big" + link[chunkSize-1:] + " end"},
		"text before the last chunks": {"see " + link + value[228:] + " end", "see " + link[:len(link)-(chunkSize-1)] + "ph:secret:big end"},
		"a value cut at its end":      {"cut: " + value[:100] + " end", "cut: ph:secret:big end"},
		"a value cut at both ends":    {"cut: " + value[5:100] + " end", "cut: ph:secret:big end"},
		"a value with a hole in it":   {"cut: " + value[:60] + strings.Repeat(".", 30) + value[120:] + " end", "cut: ph:secret:big........ph:secret:big end"},
	} {
		out, report := ix.Redact([]byte(tc.text))
		if string(out) != tc.want || report.Inventory == 0 || !report.Findings[0].Partial {
			t.Errorf("%s: %+v\n got  %s\n want %s", name, report.Findings, out, tc.want)
		}
	}
}

// A base64 match takes the whole run it sits in, and a run holds '=' only as
// padding at its end. The name before an assignment is no part of it.
func TestAnEncodedRunStopsAtAnAssignment(t *testing.T) {
	password := randomString(t, alnum, 31)
	ix := build(t, secret{ID: "pw", Value: password})
	padded := base64.StdEncoding.EncodeToString([]byte(password))
	if !strings.HasSuffix(padded, "==") {
		t.Fatalf("the test needs padding: %s", padded)
	}
	bare, urlSafe := strings.TrimRight(padded, "="), base64.RawURLEncoding.EncodeToString([]byte("id-"+password))
	for text, want := range map[string]string{
		"CONFIG=" + padded + "\nNEXT=1":                       "CONFIG=ph:secret:pw\nNEXT=1",
		"API_KEY=" + bare + "\nNEXT=1":                        "API_KEY=ph:secret:pw\nNEXT=1",
		"export B64=" + padded:                                "export B64=ph:secret:pw",
		"password: " + padded + "\n":                          "password: ph:secret:pw\n",
		"https://example.com/cb?state=" + urlSafe + "&next=1": "https://example.com/cb?state=ph:secret:pw&next=1",
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("deploy:"+password)): "Authorization: Basic ph:secret:pw",
	} {
		if out, report := ix.Redact([]byte(text)); string(out) != want || report.Inventory != 1 {
			t.Errorf("%+v\n got  %s\n want %s", report.Findings, out, want)
		}
	}
}

// All of a URL but its password is structure, which no piece of the URL is
// found by alone. That holds when the password is written with an escape
// (%40), so that its own text is not in the URL: another URL to the same host
// is left as it is.
func TestAURLWithAnEscapedPasswordKeepsItsHostAsStructure(t *testing.T) {
	host := "@db-primary.internal.example.com:5432/app"
	for written, password := range map[string]string{
		"p%40ssW0rdXYZabcQ9":   "p@ssW0rdXYZabcQ9",
		"pAssW0rdXYZabcQ9xx":   "pAssW0rdXYZabcQ9xx",
		"p%2fss%3aW0rd%40XYZ9": "p/ss:W0rd@XYZ9",
	} {
		value := "postgres://app:" + written + host
		if from, to, ok := passwordSpan(value); !ok || value[from:to] != written {
			t.Errorf("%s: the password is not where passwordSpan says", written)
		}
		ix := build(t, secret{ID: "db", Value: value})
		other := "postgres://reader" + host + "?sslmode=require and postgres://app" + host
		if out, report := ix.Redact([]byte(other)); string(out) != other || report.Inventory != 0 {
			t.Errorf("%s: another URL to the host was replaced\n%s", written, out)
		}
		for _, text := range []string{"DB=" + value + " ", "the password is " + password + " for now", "user app:" + written + " at the host"} {
			if out, report := ix.Redact([]byte(text)); bytes.Contains(out, []byte(written)) || bytes.Contains(out, []byte(password)) || report.Inventory == 0 {
				t.Errorf("%s: the password was left\n%s", written, out)
			}
		}
	}
	for _, value := range []string{"postgres://app@db.internal/app", "https://example.com/a:b@c", "not a url at all"} {
		if _, _, ok := passwordSpan(value); ok {
			t.Errorf("%s has no password", value)
		}
	}
	// The decoy that tells structure from secret has every form as long as the
	// value's, whatever the secret part is made of, or the form would go
	// without one.
	for _, value := range []string{
		"postgres://app:p%40ss!W0rd$~" + host,
		"https://deploy:пароль-密码\u2028é@git.internal/repo",
		"sk_live_пароль密码" + randomString(t, alnum, 12),
		fakePEM(t),
	} {
		mask := weakMask(value)
		if mask == nil {
			t.Fatalf("%q has no structure", value)
		}
		decoy := decoyOf(value, mask)
		forms, decoys := encodedForms(value), encodedForms(decoy)
		if decoy == value || len(forms) != len(decoys) {
			t.Fatalf("%q: the decoy is the value, or has other forms", value)
		}
		for i := range forms {
			if len(forms[i].bytes) != len(decoys[i].bytes) {
				t.Errorf("%q: the %s form of the decoy is %d bytes, the value's %d", value, forms[i].name, len(decoys[i].bytes), len(forms[i].bytes))
			}
		}
	}
}

// The key block rule takes a block that begins with key material. Two string
// constants that hold the armour lines, with code between them, are no block:
// the header is reported and the source is left as it is.
func TestArmourConstantsInSourceAreNotAKeyBlock(t *testing.T) {
	ix := build(t)
	for _, source := range []string{
		"package pemutil\n\nconst (\n\tbegin = \"-----BEGIN PRIVATE KEY-----\"\n\tend   = \"-----END PRIVATE KEY-----\"\n)\n\nfunc Wrap(b64 string) string {\n\treturn begin + \"\\n\" + b64 + \"\\n\" + end\n}\n",
		"const begin = \"-----BEGIN PRIVATE KEY-----\"\n\nfunc parse(s string) error {\n\tif !strings.HasPrefix(s, begin) { return errBad }\n\treturn nil\n}\n\nconst end = \"-----END PRIVATE KEY-----\"\n",
		"if (pem.startsWith('-----BEGIN RSA PRIVATE KEY-----') && pem.trim().endsWith('-----END RSA PRIVATE KEY-----')) {\n",
		"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
	} {
		out, findings := scanned(t, ix, source)
		if out != source || len(findings) != 1 || findings[0].Rule != "private-key-header" || findings[0].Action != actionAlert {
			t.Errorf("%+v\n%s", findings, out)
		}
	}

	// A key is taken whole however it is carried.
	key := strings.TrimSpace(fakePEM(t))
	lines := strings.Split(key, "\n")
	body := lines[1 : len(lines)-1]
	pieces := "var key = \"" + lines[0] + "\\n\" +\n"
	for _, line := range body {
		pieces += "\t\"" + line + "\\n\" +\n"
	}
	pieces += "\t\"" + lines[len(lines)-1] + "\"\n"
	for name, text := range map[string]string{
		"as it is":                 key + "\n",
		"with carriage returns":    strings.ReplaceAll(key, "\n", "\r\n"),
		"indented":                 "    " + strings.ReplaceAll(key, "\n", "\n    "),
		"with a literal \\n":       "TLS_KEY=\"" + strings.ReplaceAll(key, "\n", "\\n") + "\"",
		"escaped twice":            "{\"key\":\"" + strings.ReplaceAll(key, "\n", "\\\\n") + "\"}",
		"on one line":              strings.ReplaceAll(key, "\n", " "),
		"in pieces of a string":    pieces,
		"quoted in a reply":        "> " + strings.ReplaceAll(key, "\n", "\n> "),
		"commented out":            "# " + strings.ReplaceAll(key, "\n", "\n# "),
		"in a block comment":       "/*\n * " + strings.ReplaceAll(key, "\n", "\n * ") + "\n */",
		"encrypted, with a header": "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----\n",
	} {
		out, findings := scanned(t, ix, text)
		if len(findings) != 1 || findings[0].Rule != "private-key-block" || findings[0].Action != actionRedact || strings.Contains(out, "PRIVATE KEY") {
			t.Errorf("%s: %+v\n%s", name, findings, out)
		}
		for _, line := range body {
			if strings.Contains(out, line) {
				t.Errorf("%s: a line of the key was left\n%s", name, out)
			}
		}
	}
}

// A JSON value under a secret-sounding key is held to what a value written
// after such a name in text is: a path or a word with no digit in it is no
// secret in either place.
func TestAPathUnderAKeywordKeyIsNotASecret(t *testing.T) {
	ix := build(t)
	path := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	for _, text := range []string{
		`{"token":"` + path + `"}`,
		`{"auth":{"bearer_token":"` + path + `","password":"correct-horse-battery-staple"}}`,
		"token: " + path + "\npassword: correct-horse-battery-staple\n",
	} {
		if r := apply(ix, modelRequest(text)); r.Changed || len(r.Rules) != 0 {
			t.Errorf("%s: %+v", text, r.Rules)
		}
	}
	value := opaque(t, 32)
	for _, text := range []string{`{"token":"` + value + `"}`, "token: " + value} {
		r := apply(ix, modelRequest(text))
		if bytes.Contains(r.Out, []byte(value)) || len(r.Rules) != 1 || r.Rules[0].Rule != "keyword-high-entropy" {
			t.Errorf("%s: %+v", text, r.Rules)
		}
	}
}

// An Azure storage key has no prefix, and is taken by the name it follows. In
// JSON that a tool printed the name is the key the value sits under, which is
// all there is to go by: under one of its names the value is replaced, and
// under any other it is 64 bytes of base64 like any digest.
func TestAnAzureKeyUnderItsNameInJSONIsReplaced(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(randomBytes(t, 64))
	ix := build(t)
	for _, name := range []string{"AccountKey", "accountKey", "storageAccountKey", "account_key", "primary-storage-key"} {
		r := apply(ix, modelRequest(`{"name":"ordersprod","`+name+`":"`+key+`"}`))
		if bytes.Contains(r.Out, []byte(key)) || len(r.Rules) != 1 || r.Rules[0].Rule != "azure-storage-key-value" || r.Rules[0].Placeholder != "ph:azure_storage_key:1" {
			t.Errorf("%s: %+v", name, r.Rules)
		}
	}
	for _, name := range []string{"value", "sha512", "contentMD"} {
		if r := apply(ix, modelRequest(`{"keyName":"key1","`+name+`":"`+key+`"}`)); r.Changed || len(r.Rules) != 0 {
			t.Errorf("%s: %+v", name, r.Rules)
		}
	}
}

// Phase writes its tokens in lower-case hex. A token whose hex was put in
// upper case on the way, all of it or some of its key shares, is the same
// token and is replaced whole.
func TestAPhaseTokenInUpperCaseHexIsReplacedWhole(t *testing.T) {
	ix := build(t)
	for kind, label := range map[string]string{"pss_user:v1:": "phase_pat", "pss_service:v2:": "phase_service_token", "pss_agent:v1:": "phase_agent_token"} {
		parts := []string{randomHex(t, 32), randomHex(t, 32), randomHex(t, 32), randomHex(t, 32)}
		lower := kind + strings.Join(parts, ":")
		for name, token := range map[string]string{
			"lower case":        lower,
			"upper case":        kind + strings.ToUpper(strings.Join(parts, ":")),
			"upper-case shares": kind + parts[0] + ":" + strings.ToUpper(parts[1]) + ":" + parts[2] + ":" + strings.ToUpper(parts[3]),
		} {
			for _, before := range []string{"here: ", "see the docs, then ", "export PHASE_SERVICE_TOKEN="} {
				out, findings := scanned(t, ix, before+token+" ok")
				if len(findings) != 1 || findings[0].Label != label || out != before+findings[0].Placeholder+" ok" {
					t.Errorf("%s%s, %s: %+v\n%s", before, kind, name, findings, out)
				}
			}
		}
	}
}

// A base64 or hex match takes the whole run it sits in. A run made of one
// value written over and over is taken once, not once for each copy: the cost
// stays linear in the run.
func TestARunOfRepeatedCopiesIsTakenOnce(t *testing.T) {
	limit := 100 * time.Millisecond
	if raceEnabled {
		limit *= 10
	}
	value := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "v", Value: value})
	text := []byte("x " + strings.Repeat(hex.EncodeToString([]byte(value)), 4000) + " y")
	best := time.Hour
	var out []byte
	var report *Report
	for i := 0; i < 3; i++ {
		started := time.Now()
		out, report = ix.Redact(text)
		best = min(best, time.Since(started))
	}
	t.Logf("%d KB of copies scanned in %v", len(text)>>10, best)
	if string(out) != "x ph:secret:v y" || report.Inventory != 1 {
		t.Fatalf("%d found: %.60s", report.Inventory, out)
	}
	if best > limit {
		t.Fatalf("scanning took %v, over %v", best, limit)
	}
}

// Ranges found in bytes that were rewritten are mapped back to the bytes that
// were scanned. With thousands of replacements before thousands of ranges each
// one still maps to its own place, and the mapping walks the replacements
// once, not once for every range.
func TestManyRangesMapBackInOnePass(t *testing.T) {
	limit := 250 * time.Millisecond
	if raceEnabled {
		limit *= 10
	}
	first, second := randomString(t, alnum, 24), randomString(t, alnum, 24)
	ix := build(t, secret{ID: "a", Value: first}, secret{ID: "b", Value: second})
	// The second value is in base64 twice over, so it is found by decoding a
	// run, after the first pass replaced every copy of the first.
	inner := base64.StdEncoding.EncodeToString([]byte("xx " + second + " yy"))
	run := base64.StdEncoding.EncodeToString([]byte("see " + inner + " there"))
	const copies = 20000
	text := []byte(strings.Repeat(first+" ", copies) + strings.Repeat(run+" ", copies))
	best := time.Hour
	var matches []Match
	for i := 0; i < 3; i++ {
		started := time.Now()
		ix.mu.RLock()
		_, _, _, reps, _ := ix.scanBlock(text, "", newScanState(), true, ix.rules)
		ix.mu.RUnlock()
		best = min(best, time.Since(started))
		matches = matches[:0]
		for _, r := range reps {
			matches = append(matches, Match{Finding: r.hit.finding(), Start: r.start, End: r.end})
		}
	}
	t.Logf("%d ranges in %d KB mapped in %v", len(matches), len(text)>>10, best)
	if len(matches) != 2*copies {
		t.Fatalf("%d ranges, want %d", len(matches), 2*copies)
	}
	for i, m := range matches {
		want, placeholder := first, "ph:secret:a"
		if i >= copies {
			want, placeholder = run, "ph:secret:b"
		}
		if string(text[m.Start:m.End]) != want || m.Placeholder != placeholder {
			t.Fatalf("range %d is %d to %d, %s", i, m.Start, m.End, m.Placeholder)
		}
	}
	if best > limit {
		t.Fatalf("scanning took %v, over %v", best, limit)
	}

	// Asked out of order, a position is still mapped from the start.
	reps := []rep{{start: 10, end: 40, hit: hit{placeholder: "ph:secret:a"}}, {start: 50, end: 52}, {start: 60, end: 64, hit: hit{placeholder: "ph:secret:b"}}}
	back := positions{reps: reps}
	for _, tc := range []struct {
		pos, want int
		end       bool
	}{{5, 5, false}, {10, 10, false}, {15, 10, false}, {15, 40, true}, {21, 40, false}, {41, 60, false}, {45, 64, true}, {52, 64, false}, {60, 72, false}, {3, 3, false}, {30, 49, false}} {
		if got := back.of(tc.pos, tc.end); got != tc.want {
			t.Errorf("position %d maps to %d, want %d", tc.pos, got, tc.want)
		}
	}
}

// A finding's path is as long as the keys above its string. A report lists
// MaxFindings and only counts the rest, so only those are given a path: past
// the cap a long key does not cost a copy of itself for every finding more.
func TestPathsAreBuiltOnlyForListedFindings(t *testing.T) {
	password := randomString(t, alnum, 24)
	ix := build(t, secret{ID: "pw", Value: password})
	key := strings.Repeat("k", 8<<10)
	scan := func(content func(values []string) any, count int) uint64 {
		values := make([]string, count)
		for i := range values {
			values[i] = password
		}
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": content(values)}}})
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out, report, err := ix.RewriteJSON(body, ScanOptions{})
		runtime.ReadMemStats(&after)
		if err != nil || bytes.Contains(out, []byte(password)) || report.Inventory != count || len(report.Findings) != MaxFindings || !report.Truncated {
			t.Fatalf("%v, %d found of %d, %d listed", err, report.Inventory, count, len(report.Findings))
		}
		for i, f := range report.Findings {
			if want := "/" + strconv.Itoa(i); len(f.Path) < len(key) || f.Path[len(f.Path)-len(want):] != want {
				t.Fatalf("finding %d has the path %.40s...%s", i, f.Path, f.Path[len(f.Path)-8:])
			}
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	for name, content := range map[string]func(values []string) any{
		"in the body": func(values []string) any { return map[string]any{key: map[string]any{"v": values}} },
		"in JSON held in a string": func(values []string) any {
			inner, _ := json.Marshal(map[string]any{key: map[string]any{"v": values}})
			return string(inner)
		},
	} {
		// 10,000 findings more, every one past the cap. Scanning their strings
		// allocates some 20 MB; a path for each would add 80 MB of keys.
		few, many := scan(content, 6000), scan(content, 16000)
		if more := (int64(many) - int64(few)) >> 20; more > 50 {
			t.Errorf("%s: 10,000 findings past the cap cost %d MB", name, more)
		} else {
			t.Logf("%s: 10,000 findings past the cap cost %d MB", name, more)
		}
	}
}
