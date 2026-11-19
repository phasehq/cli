package censor

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
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
