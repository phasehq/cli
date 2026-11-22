package censor

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
	"time"
)

// A thinking block is signed by the provider; an edited one is refused, which
// breaks the session. Its text is scanned and reported, never changed, whatever
// order its members come in. The same values elsewhere are replaced.
func TestSignedBlocksAreLeftAsTheyWere(t *testing.T) {
	value := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd"
	ix := build(t, secret{ID: "db", Type: "secret", Value: value})
	ruleValue := githubToken(t)
	thought := "the key is " + value + " and the token is " + ruleValue
	signature := "EqQBCkYIBBgCKkB" + strings.Repeat("Q", 120)
	// The signature comes before the type here, to show order does not matter.
	signedBlock := `{"signature":"` + signature + `","thinking":"` + thought + `","type":"thinking"}`
	redacted := `{"type":"redacted_thinking","data":"` + value + `"}`
	encrypted := `{"type":"reasoning","encrypted_content":"` + value + `"}`
	body := []byte(`{"model":"claude","messages":[` +
		`{"role":"assistant","content":[` + signedBlock + `,` + redacted + `,{"type":"text","text":"` + thought + `"}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"` + thought + `"}]}],` +
		`"input":[` + encrypted + `]}`)
	out, report, err := ix.RewriteJSON(body, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{signedBlock, redacted, encrypted} {
		if !bytes.Contains(out, []byte(kept)) {
			t.Fatalf("a signed block was changed:\n%s", out)
		}
	}
	// Two more places hold each value: the text block and the tool result.
	if got := bytes.Count(out, []byte(value)); got != 3 {
		t.Fatalf("the value is left in %d places, want 3 (the signed blocks only)", got)
	}
	if got := bytes.Count(out, []byte(ruleValue)); got != 1 {
		t.Fatalf("the token is left in %d places, want 1 (the thinking block only)", got)
	}
	if report.Inventory != 2 || report.Redacted != 2 {
		t.Fatalf("inventory %d redacted %d, want 2 and 2", report.Inventory, report.Redacted)
	}
	// thinking (value and token), redacted_thinking data, encrypted_content.
	if report.Left != 4 {
		t.Fatalf("left %d, want 4", report.Left)
	}
	for _, f := range report.Findings {
		signed := strings.HasPrefix(f.Path, "/messages/0/content/0/") || strings.HasPrefix(f.Path, "/messages/0/content/1/") || strings.HasPrefix(f.Path, "/input/")
		if signed != (f.Action == actionLeft) {
			t.Fatalf("finding at %s has action %s", f.Path, f.Action)
		}
	}
	var parsed any
	if json.Unmarshal(out, &parsed) != nil {
		t.Fatal("the rewritten body is not JSON")
	}
}

// githubToken makes a classic GitHub token with a valid checksum.
func githubToken(t *testing.T) string {
	body := randomString(t, alnum, 30)
	return "ghp_" + body + base62(crc32.ChecksumIEEE([]byte(body)), 6)
}

// Keyword values end at '&', and PWD and OLDPWD followed by a path are a
// directory, not a password.
func TestKeywordValueEdges(t *testing.T) {
	ix := build(t)
	refresh := "sk-ant-ort01-Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq"
	out, _ := ix.Redact([]byte("grant_type=refresh_token&refresh_token=" + refresh + "&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"))
	if bytes.Contains(out, []byte(refresh)) {
		t.Fatalf("the refresh token was not replaced: %s", out)
	}
	if !bytes.HasSuffix(out, []byte("&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e")) {
		t.Fatalf("what follows '&' was replaced too: %s", out)
	}
	out, _ = ix.Redact([]byte("GET /v1/items?token=Q7tZ2mK9pL4vX8rN1wB6yC3d&page=2"))
	if !bytes.HasSuffix(out, []byte("&page=2")) || bytes.Contains(out, []byte("Q7tZ2mK9pL4vX8rN1wB6yC3d")) {
		t.Fatalf("query: %s", out)
	}
	env := "OLDPWD=/Users/dev/projects/app-v2\nPWD=/Users/dev/projects/app-v3/src\nHOME=/Users/dev"
	out, report := ix.Redact([]byte(env))
	if string(out) != env || report.Alerts != 0 {
		t.Fatalf("a working directory was taken for a password: %s (alerts %d)", out, report.Alerts)
	}
	jsonEnv := []byte(`{"messages":[{"role":"user","content":"{\"PWD\":\"/Users/dev/projects/app-v3/src\"}"}]}`)
	if out, report, _ := ix.RewriteJSON(jsonEnv, ScanOptions{}); !bytes.Equal(out, jsonEnv) || report.Alerts != 0 {
		t.Fatalf("a JSON PWD path was taken for a password: %s", out)
	}
	// A connection string's pwd= still counts.
	out, _ = ix.Redact([]byte("Server=db;Uid=app;Pwd=Xk82jfLq0pA9mZ3vT7wQ;"))
	if bytes.Contains(out, []byte("Xk82jfLq0pA9mZ3vT7wQ")) {
		t.Fatalf("pwd= in a connection string was not replaced: %s", out)
	}
}

// A call can be limited to some rules; indexed values are found regardless,
// and the cache never hands one rule set's result to another.
func TestRulesOnlyLimitsACall(t *testing.T) {
	value := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd"
	ix := build(t, secret{ID: "db", Type: "secret", Value: value})
	phaseOnly, err := DefaultRules().Only("phase-user-token", "phase-service-token", "phase-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DefaultRules().Only("no-such-rule"); err == nil {
		t.Fatal("an unknown id was accepted")
	}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	phaseToken := "pss_service:v2:" + strings.Repeat("ab", 32) + ":" + strings.Repeat("cd", 32) + ":" + strings.Repeat("ef", 32) + ":" + strings.Repeat("01", 32)
	text := "bearer token " + jwt + " and " + value + " and " + phaseToken + strings.Repeat(" padding", 40)
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}})

	limited, report, err := ix.RewriteJSON(body, ScanOptions{Rules: phaseOnly})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(limited, []byte(jwt)) || bytes.Contains(limited, []byte(value)) || bytes.Contains(limited, []byte(phaseToken)) {
		t.Fatalf("limited call: %s", limited)
	}
	for _, f := range report.Findings {
		if f.Kind == kindRule && !strings.HasPrefix(f.Rule, "phase-") {
			t.Fatalf("rule %s ran in a limited call", f.Rule)
		}
	}
	// The same string again with every rule: the cache must not answer it.
	full, _, _ := ix.RewriteJSON(body, ScanOptions{})
	if bytes.Contains(full, []byte(jwt)) {
		t.Fatal("the limited call's cached result was used for a full one")
	}
	if matches := ix.FindWith([]byte("/v1/x?a="+jwt+"&token="+jwt), ScanOptions{Rules: phaseOnly}); len(matches) != 0 {
		t.Fatalf("FindWith applied rules it was not given: %+v", matches)
	}
	if out, _ := ix.RedactWith([]byte("bearer "+jwt), ScanOptions{Rules: phaseOnly}); !bytes.Contains(out, []byte(jwt)) {
		t.Fatal("RedactWith applied rules it was not given")
	}
}

// Whatever is registered, a scan stays linear in the body: a value of one
// repeated block, and entries whose chunks all share one rolling hash, leave a
// 100 KB body that matches them cheap to scan.
func TestScanCostStaysLinear(t *testing.T) {
	limit := 100 * time.Millisecond
	if raceEnabled {
		limit *= 10
	}
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	block := "Ab3$xY9!kLm2"
	repeated, err := IndexValue(key, "secret", "repeat", strings.Repeat(block, 5000))
	if err != nil || !repeated.Protected() {
		t.Fatalf("the repeated value was not indexed: %v", err)
	}
	if err := ix.Add(repeated); err != nil {
		t.Fatal(err)
	}
	// Hostile entries: every chunk of every form has the block's rolling hash,
	// so every aligned position of the body leads to all of them.
	roll := key.roll([]byte(block))
	for id := 0; id < 4; id++ {
		e := &Entries{Version: EntriesVersion, Type: "secret", ID: "same-hash-" + string(rune('a'+id))}
		for i := 0; i < maxFormsPerValue; i++ {
			const n = 8
			f := Form{Form: formRaw, Length: n * chunkSize, Weak: make([]byte, 1), MACs: make([]byte, n*macSize)}
			for j := 0; j < n; j++ {
				schemes[EntriesVersion].appendLookup(&f, roll)
			}
			if _, err := rand.Read(f.MACs); err != nil {
				t.Fatal(err)
			}
			e.Forms = append(e.Forms, f)
		}
		if err := ix.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	// An ordinary value is still found next to all of that.
	ordinary := "Q7tZ2mK9pL4vX8rN1wB6yC3dF5"
	plain, _ := IndexValue(key, "secret", "plain", ordinary)
	if err := ix.Add(plain); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat(block, (100<<10)/len(block)) + " " + ordinary)
	best := time.Hour
	var report *Report
	var out []byte
	for i := 0; i < 3; i++ {
		started := time.Now()
		out, report = ix.Redact(body)
		best = min(best, time.Since(started))
	}
	t.Logf("100 KB body scanned in %v", best)
	if report.Inventory < 2 || bytes.Contains(out, []byte(ordinary)) || bytes.Contains(out, []byte(block+block)) {
		t.Fatalf("matching was weakened: inventory %d", report.Inventory)
	}
	if best > limit {
		t.Fatalf("scanning took %v, over %v", best, limit)
	}
}

// The exemption for provider-signed text belongs to the request's own
// structure. JSON that a tool result or a file merely contains, shaped like a
// thinking block or holding an encrypted_content key, is ordinary text: what
// is found in it is replaced.
func TestSignedExemptionStopsAtTheRequestItself(t *testing.T) {
	value := "Zq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pq5Vd"
	ix := build(t, secret{ID: "db", Type: "secret", Value: value})
	token := githubToken(t)
	cases := map[string]string{
		"a thinking block":      `{"type":"thinking","thinking":"` + value + `"}`,
		"type after the text":   `{"thinking":"the token is ` + token + `","signature":"` + value + `","type":"thinking"}`,
		"redacted thinking":     `{"type":"redacted_thinking","data":"` + value + `"}`,
		"encrypted content":     `{"type":"reasoning","encrypted_content":"` + value + `"}`,
		"under encrypted":       `{"encrypted_content":{"blob":["` + value + `"]}}`,
		"in a list of blocks":   `[{"type":"text","text":"hello"},{"type":"thinking","thinking":"` + value + `","signature":"sig"}]`,
		"two levels of strings": `{"output":` + string(mustJSON(`{"type":"thinking","thinking":"`+value+`"}`)) + `}`,
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"model": "m", "messages": []any{
				map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": inner}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			out, report, err := ix.RewriteJSON(body, ScanOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(out, []byte(value)) || bytes.Contains(out, []byte(token)) {
				t.Fatalf("a value inside a string's JSON went out unchanged: %s", out)
			}
			if report.Left != 0 || report.Inventory == 0 || !report.Changed {
				t.Fatalf("left %d, inventory %d, changed %v", report.Left, report.Inventory, report.Changed)
			}
			for _, f := range report.Findings {
				if f.Action == actionLeft {
					t.Fatalf("finding at %s was left", f.Path)
				}
			}
			if !json.Valid(out) {
				t.Fatal("the rewritten body is not JSON")
			}
		})
	}

	// The request's own signed block is still left alone, including when the
	// signed string itself holds JSON.
	thinking := `{\"type\":\"thinking\",\"thinking\":\"` + value + `\"}`
	signedBlock := `{"type":"thinking","thinking":"` + thinking + `","signature":"sig"}`
	body := []byte(`{"model":"m","messages":[{"role":"assistant","content":[` + signedBlock + `]}]}`)
	out, report, err := ix.RewriteJSON(body, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, body) || report.Changed || report.Left != 1 || report.Inventory != 0 {
		t.Fatalf("the request's own thinking block: changed %v, left %d, inventory %d", report.Changed, report.Left, report.Inventory)
	}
}
