package censortest

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestMissesAreFoundAndNamed(t *testing.T) {
	value := "Zq8vLm2Rt5Xw9Kp3Hd7Nf4Bc"
	v := NewVerifier([]Entry{
		{ID: "api", Value: value},
		{ID: "db", Value: "postgres://app:Qw3Er5Ty7Ui9Op1As3Df5Gh@db.internal:5432/app"},
		{ID: "pg", Value: "postgres", Expect: "too_short"},
	})
	body, _ := json.Marshal(map[string]any{"messages": []any{
		map[string]any{"content": "token " + base64.StdEncoding.EncodeToString([]byte(value))},
		map[string]any{"content": "connect to db.internal:5432 as app, password Qw3Er5Ty7Ui9Op1As3Df5Gh"},
		map[string]any{"content": "image: postgres:16"},
	}})
	misses := v.Check(body)
	want := map[string]Miss{
		"api": {ID: "api", Form: "base64"},
		"db":  {ID: "db", Part: "url-password", Form: "raw"},
		"pg":  {ID: "pg", Form: "raw", Expected: true},
	}
	if len(misses) != len(want) {
		t.Fatalf("%+v", misses)
	}
	for _, miss := range misses {
		if want[miss.ID] != miss {
			t.Fatalf("got %+v, want %+v", miss, want[miss.ID])
		}
	}
	if clean := v.Check([]byte(`{"content":"ph:secret:api and ph:secret:db"}`)); len(clean) != 0 {
		t.Fatalf("%+v", clean)
	}
}

func TestFragmentsOfAValueAreMisses(t *testing.T) {
	v := NewVerifier([]Entry{{ID: "k", Value: "AbCdEfGh1234IjKlMnOp5678QrStUv"}})
	misses := v.Check([]byte("it begins AbCdEfGh1234Ij..."))
	if len(misses) != 1 || misses[0].Form != "fragment-or-embedded" {
		t.Fatalf("%+v", misses)
	}
}

func TestFixtureHoldsItsValues(t *testing.T) {
	fixture := NewFixture()
	if len(fixture.Entries) < 25 || fixture.RuleOnly != 2 || len(fixture.Files) < 20 {
		t.Fatalf("%d entries, %d rule-only, %d files", len(fixture.Entries), fixture.RuleOnly, len(fixture.Files))
	}
	v := NewVerifier(fixture.Entries)
	found := map[string]bool{}
	for _, content := range fixture.Files {
		for _, miss := range v.Check([]byte(content)) {
			found[miss.ID] = true
		}
	}
	for _, entry := range fixture.Entries {
		// The Helm value is only there compressed, which the verifier does not undo.
		if !found[entry.ID] && entry.ID != "helm_values_api_key" {
			t.Errorf("%s is in no file", entry.ID)
		}
	}
	dir := filepath.Join(t.TempDir(), "repo")
	if err := fixture.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Write(dir); err == nil {
		t.Fatal("writing over an existing directory should fail")
	}
}
