package proxy

import "testing"

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
