package proxy

import (
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestGlobMatchMirrorsFnmatchBracketClassesAndMalformedLiterals(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"[ab]", "a", true},
		{"[ab]", "c", false},
		{"[!a]", "b", true},
		{"[!a]", "a", false},
		{"[a-c]", "b", true},
		{"[]a]", "]", true},
		{"[z-a]", "z", false},
		{"[", "[", true},
		{"[abc", "[abc", true},
		{"[[]", "[", true},
		{"a*b", "a/path/b", true},
	}
	for _, test := range tests {
		if got := globMatch(test.pattern, test.value); got != test.want {
			t.Errorf("globMatch(%q, %q)=%t, want %t", test.pattern, test.value, got, test.want)
		}
	}
}

func TestMatchHostRuleRefusesPathsThatOnlyMatchOnceCleaned(t *testing.T) {
	rule := agentapi.HostRule{Match: "suffix", Value: "s3.us-east-1.amazonaws.com", Path: "/allowed/*"}
	for requestPath, want := range map[string]bool{
		"/allowed/key":                true,
		"/allowed/dir/":               true,
		"/allowed/a%20b":              true,
		"/outside/../allowed/key":     false,
		"/outside/%2E%2E/allowed/key": false,
		"/outside%2F..%2Fallowed/key": false,
		"/allowed/./key":              false,
		"//allowed/key":               false,
		"/allowed/../outside":         false,
	} {
		if got := MatchHostRule(rule, "bucket.s3.us-east-1.amazonaws.com", 443, requestPath); got != want {
			t.Errorf("MatchHostRule(%q)=%t, want %t", requestPath, got, want)
		}
	}
	// S3 keys "allowed" and "allowed/" are different objects.
	for rulePath, requests := range map[string]map[string]bool{
		"/allowed":  {"/allowed": true, "/allowed/": false},
		"/allowed/": {"/allowed/": true, "/allowed": false},
	} {
		rule.Path = rulePath
		for requestPath, want := range requests {
			if got := MatchHostRule(rule, "bucket.s3.us-east-1.amazonaws.com", 443, requestPath); got != want {
				t.Errorf("rule %q MatchHostRule(%q)=%t, want %t", rulePath, requestPath, got, want)
			}
		}
	}
}
