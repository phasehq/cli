package cmd

import "testing"

func TestChangesTypeOnly(t *testing.T) {
	tests := []struct {
		name            string
		secretType      string
		randomType      string
		override        bool
		stdinIsTerminal bool
		want            bool
	}{
		{name: "type from a terminal", secretType: "sealed", stdinIsTerminal: true, want: true},
		{name: "type with a piped value", secretType: "secret", stdinIsTerminal: false, want: false},
		{name: "no type", stdinIsTerminal: true, want: false},
		{name: "type with random", secretType: "secret", randomType: "hex", stdinIsTerminal: true, want: false},
		{name: "type with override", secretType: "secret", override: true, stdinIsTerminal: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := changesTypeOnly(tt.secretType, tt.randomType, tt.override, tt.stdinIsTerminal)
			if got != tt.want {
				t.Fatalf("changesTypeOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}
