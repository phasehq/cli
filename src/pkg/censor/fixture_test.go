package censor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/censortest"
)

// TestFixtureEndToEnd sends every file of the fake-secret repository through the
// index as a tool result, and checks what is left with the independent verifier:
// the run the lab did, without a harness or a network.
func TestFixtureEndToEnd(t *testing.T) {
	fixture := censortest.NewFixture()
	var secrets []secret
	for _, entry := range fixture.Entries {
		if entry.Expect != "rule" {
			secrets = append(secrets, secret{ID: entry.ID, Type: entry.Type, Value: entry.Value})
		}
	}
	ix, entries := buildWithEntries(t, newKey(t), secrets...)
	for id, e := range entries {
		for _, u := range e.Unprotected {
			t.Logf("not indexed: %s %s: %s", id, u.Part, u.Reason)
		}
	}
	verifier := censortest.NewVerifier(fixture.Entries)

	names := make([]string, 0, len(fixture.Files))
	for name := range fixture.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	found := map[string]bool{}
	ruleLabels := map[string]int{}
	var unexpected []string
	for _, name := range names {
		body, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{
			map[string]any{"role": "user", "content": "read " + name},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "content": fixture.Files[name]}}},
		}})
		result := apply(ix, body)
		var forms []string
		for _, hit := range result.Hits {
			found[strings.TrimPrefix(hit.Placeholder, "ph:"+placeholderType(hit.Placeholder)+":")] = true
			form := hit.Form
			if hit.Part != "" {
				form += "(" + hit.Part + ")"
			}
			if hit.Partial {
				form += "/partial"
			}
			forms = append(forms, hit.Placeholder+":"+form)
		}
		for _, hit := range result.Rules {
			ruleLabels[hit.Label]++
			forms = append(forms, fmt.Sprintf("rule:%s(%s %d)", hit.Label, hit.Action, hit.Score))
		}
		var missText []string
		for _, miss := range verifier.Check(result.Out) {
			text := fmt.Sprintf("%s/%s%s", miss.ID, miss.Form, map[bool]string{true: " (expected)"}[miss.Expected])
			missText = append(missText, text)
			if !miss.Expected {
				unexpected = append(unexpected, name+": "+text)
			}
		}
		if !json.Valid(result.Out) {
			t.Errorf("%s: rewritten body is not JSON", name)
		}
		t.Logf("%-30s hits %s | misses %s", name, strings.Join(forms, ", "), strings.Join(missText, ", "))
	}
	for _, entry := range fixture.Entries {
		if (entry.Expect == "" || entry.Expect == "hit") && !found[entry.ID] {
			t.Errorf("%s (%s) was never caught", entry.ID, entry.Where)
		}
	}
	if !found["helm_values_api_key"] {
		t.Error("the gzip+base64 Helm value was not caught")
	}
	if ruleLabels["keyword_secret"] < 3 {
		t.Errorf("the keyword-only values were not all caught: %v", ruleLabels)
	}
	if ruleLabels["phase_service_token"] == 0 || ruleLabels["phase_pat"] == 0 {
		t.Errorf("the Phase tokens outside the entries were not caught by rules: %v", ruleLabels)
	}
	if len(unexpected) > 0 {
		t.Errorf("unexpected misses:\n%s", strings.Join(unexpected, "\n"))
	}
}

func placeholderType(placeholder string) string {
	parts := strings.SplitN(placeholder, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}
