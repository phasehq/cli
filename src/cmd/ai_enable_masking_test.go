package cmd

import (
	"testing"

	"github.com/phasehq/cli/pkg/config"
)

func TestResolveAIEnableMasking(t *testing.T) {
	tests := []struct {
		name         string
		mask, noMask bool
		previous     *config.AIConfig
		interactive  bool
		want         bool
		wantErr      bool
	}{
		{name: "mask flag", mask: true, want: true},
		{name: "no-mask flag", noMask: true, want: false},
		{name: "both flags", mask: true, noMask: true, wantErr: true},
		{name: "non-interactive keeps previous choice", previous: &config.AIConfig{MaskSecretValues: false}, want: false},
		{name: "non-interactive defaults to masking", want: true},
		{name: "interactive asks", interactive: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompted := false
			prompt := func() (bool, error) { prompted = true; return false, nil }
			got, err := resolveAIEnableMasking(test.mask, test.noMask, test.previous, test.interactive, prompt)
			if (err != nil) != test.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("mask = %v, want %v", got, test.want)
			}
			if prompted != test.interactive {
				t.Fatalf("prompted = %v, want %v", prompted, test.interactive)
			}
		})
	}
}
